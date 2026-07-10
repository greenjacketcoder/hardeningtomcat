@{
    # PSScriptAnalyzer settings for HardeningTomcat.
    # Run:  Invoke-ScriptAnalyzer -Path . -Recurse -Settings .\PSScriptAnalyzerSettings.psd1
    #
    # Two rules are excluded DELIBERATELY -- these are accepted deviations, reviewed
    # in the 0.7.2 QA pass, not oversights:
    #
    # - PSAvoidUsingWriteHost: HardeningTomcat is an interactive console tool. The
    #   colored summary blocks, progress bar, and per-finding console output are the
    #   product's UI, written intentionally to the host (not to the pipeline, which
    #   carries the -PassThru result object instead). Replacing them with
    #   Write-Output would pollute the pipeline contract.
    #
    # - PSReviewUnusedParameter: every handler exposes scriptblocks with the fixed
    #   contract  param($Finding, $Cache, $Context)  (see Handlers/_CONTRACT.md).
    #   Handlers that do not need every parameter still declare all three so the
    #   engine can invoke them uniformly; the "unused" parameters are the interface.
    #
    # - PSAvoidUsingPositionalParameters (newer PSSA versions): fires only on two
    #   INTERNAL helpers with fixed, stable signatures -- New-HtResult (engine result
    #   factory, called ~8x in one loop) and the tests' Test-Op wrapper (operator
    #   table-tests, where positional '=or' '2' '1 or 2' reads like the truth table
    #   it is). Named parameters at those call sites add noise, not safety; the
    #   exported cmdlet surface uses named parameters throughout.
    ExcludeRules = @(
        'PSAvoidUsingWriteHost',
        'PSReviewUnusedParameter',
        'PSAvoidUsingPositionalParameters'
    )
}
