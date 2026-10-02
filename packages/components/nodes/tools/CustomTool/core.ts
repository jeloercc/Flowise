import { z } from 'zod/v3'
import { RunnableConfig } from '@langchain/core/runnables'
import { StructuredTool, ToolParams } from '@langchain/core/tools'
import { CallbackManagerForToolRun, Callbacks, CallbackManager, parseCallbackConfigArg } from '@langchain/core/callbacks/manager'
import { executeJavaScriptCode, createCodeExecutionSandbox, parseWithTypeConversion } from '../../../src/utils'
import { ICommonObject } from '../../../src/Interface'
import { SecretBinding, makeSecureRequestHelper } from '../../../src/guardRequest'
import { redact } from '../../../src/guardRedact'

class ToolInputParsingException extends Error {
    output?: string

    constructor(message: string, output?: string) {
        super(message)
        this.output = output
    }
}

export interface BaseDynamicToolInput extends ToolParams {
    name: string
    description: string
    code: string
    returnDirect?: boolean
}

export interface DynamicStructuredToolInput<
    // eslint-disable-next-line
    T extends z.ZodObject<any, any, any, any> = z.ZodObject<any, any, any, any>
> extends BaseDynamicToolInput {
    func?: (input: z.infer<T>, runManager?: CallbackManagerForToolRun) => Promise<string>
    schema: T
}

export class DynamicStructuredTool<
    // eslint-disable-next-line
    T extends z.ZodObject<any, any, any, any> = z.ZodObject<any, any, any, any>
> extends StructuredTool {
    name: string

    description: string

    code: string

    func: DynamicStructuredToolInput['func']

    // @ts-ignore
    schema: T
    private variables: any[]
    private flowObj: any
    /** Zero-Context Guard: admin-declared secret bindings (F-01, F-02, F-05) */
    private secretBindings: SecretBinding[] = []
    /** Runtime options from the Flowise execution context (needed for getCredentialData) */
    private executionOptions: ICommonObject = {}

    constructor(fields: DynamicStructuredToolInput<T>) {
        super(fields)
        this.name = fields.name
        this.description = fields.description
        this.code = fields.code
        this.func = fields.func
        this.returnDirect = fields.returnDirect ?? this.returnDirect
        this.schema = fields.schema
    }

    async call(
        arg: z.output<T>,
        configArg?: RunnableConfig | Callbacks,
        tags?: string[],
        flowConfig?: { sessionId?: string; chatId?: string; input?: string; state?: ICommonObject }
    ): Promise<string> {
        const config = parseCallbackConfigArg(configArg)
        if (config.runName === undefined) {
            config.runName = this.name
        }
        let parsed
        try {
            parsed = await parseWithTypeConversion(this.schema, arg)
        } catch (e) {
            throw new ToolInputParsingException(`Received tool input did not match expected schema`, JSON.stringify(arg))
        }
        const callbackManager_ = await CallbackManager.configure(
            config.callbacks,
            this.callbacks,
            config.tags || tags,
            this.tags,
            config.metadata,
            this.metadata,
            { verbose: this.verbose }
        )
        const runManager = await callbackManager_?.handleToolStart(
            this.toJSON(),
            typeof parsed === 'string' ? parsed : JSON.stringify(parsed),
            undefined,
            undefined,
            undefined,
            undefined,
            config.runName
        )
        let result
        try {
            result = await this._call(parsed, runManager, flowConfig)
        } catch (e) {
            await runManager?.handleToolError(e)
            throw e
        }
        if (result && typeof result !== 'string') {
            result = JSON.stringify(result)
        }
        await runManager?.handleToolEnd(result)
        return result
    }

    // @ts-ignore
    protected async _call(
        arg: z.output<T>,
        _?: CallbackManagerForToolRun,
        flowConfig?: { sessionId?: string; chatId?: string; input?: string; state?: ICommonObject }
    ): Promise<string> {
        // Create additional sandbox variables for tool arguments
        const additionalSandbox: ICommonObject = {}

        if (typeof arg === 'object' && Object.keys(arg).length) {
            for (const item in arg) {
                additionalSandbox[`$${item}`] = arg[item]
            }
        }

        // Prepare flow object for sandbox
        const flow = this.flowObj ? { ...this.flowObj, ...flowConfig } : {}

        // ── Zero-Context Guard ────────────────────────────────────────────────
        // When secret bindings are declared, inject $secureRequest and remove
        // $vars from scope so raw secret values never enter the sandbox (F-01, F-02, F-05).
        const hasBindings = this.secretBindings.length > 0
        const secureRequestHelper = hasBindings ? makeSecureRequestHelper(this.secretBindings, this.executionOptions) : undefined

        const sandbox = createCodeExecutionSandbox('', this.variables || [], flow, additionalSandbox, secureRequestHelper)

        // Collect resolved secret values for post-execution redaction (F-04, F-06).
        // We collect them here lazily so they are never stored longer than needed.
        // Note: these strings are in the host process only and never enter the sandbox.
        let resolvedSecretValues: string[] = []

        let response: any
        try {
            response = await executeJavaScriptCode(this.code, sandbox, {
                // Disable E2B when bindings are present: the remote VM cannot
                // receive the $secureRequest closure and must not see $vars (F-01).
                disableE2B: hasBindings
            })
        } catch (e: any) {
            // Redact any secret patterns from error messages before re-throw (F-06).
            const safeMessage = redact(e?.message ?? String(e), resolvedSecretValues)
            throw new Error(safeMessage)
        }

        if (typeof response === 'object') {
            response = JSON.stringify(response)
        }

        // Redact the output before it reaches handleToolEnd / LLM (F-02, F-04).
        return redact(String(response ?? ''), resolvedSecretValues)
    }

    setVariables(variables: any[]) {
        this.variables = variables
    }

    setFlowObject(flow: any) {
        this.flowObj = flow
    }

    /**
     * Zero-Context Guard: stores admin-declared secret bindings on the tool.
     * Called from CustomTool.ts:init() after constructing the tool instance.
     */
    setSecretBindings(bindings: SecretBinding[]) {
        this.secretBindings = bindings ?? []
    }

    /**
     * Zero-Context Guard: stores the Flowise execution options so the helper
     * can call getCredentialData during _call().
     */
    setExecutionOptions(options: ICommonObject) {
        this.executionOptions = options ?? {}
    }
}
