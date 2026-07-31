namespace TVTimeRecovery.Windows;

internal static class RecoveryArtifactContract
{
    internal const long MaximumStateBytes = 64L * 1024;
    internal const long MaximumSummaryBytes = 16L * 1024 * 1024;
    internal const long MaximumGeneratedArtifactBytes = 64L * 1024 * 1024;
    internal const long MaximumInventoryBytes = 256L * 1024 * 1024;
    internal const long MaximumDomainsBytes = 32L * 1024;

    internal static readonly IReadOnlyDictionary<string, string> RequiredArtifacts =
        new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["extraction_run_state"] = "metadata/run_state.json",
            ["extraction_inventory"] = "metadata/inventory.csv",
            ["extraction_summary"] = "metadata/summary.json",
            ["extraction_domains"] = "metadata/domains.txt",
            ["analysis_summary"] = "analysis/analysis_summary.json",
            ["cache_index"] = "analysis/cache_index.csv",
            ["movie_library"] = "analysis/movie_library.csv",
            ["watch_events"] = "analysis/watch_events.csv",
            ["episode_cache"] = "analysis/episode_cache.csv",
            ["sqlite_integrity"] = "analysis/sqlite_integrity.csv",
            ["plist_key_inventory"] = "analysis/plist_key_inventory.csv",
            ["series_library"] = "analysis/series_library.csv",
            ["watched_movies"] = "analysis/watched_movies.csv",
            ["movie_watchlist"] = "analysis/movie_watchlist.csv",
            ["favorite_shows"] = "analysis/favorite_shows.csv",
            ["favorite_movies"] = "analysis/favorite_movies.csv",
            ["episode_cache_unique"] = "analysis/episode_cache_unique.csv",
            ["watch_events_named"] = "analysis/watch_events_named.csv",
            ["trailer_references"] = "analysis/trailer_references.csv",
            ["media_url_inventory"] = "analysis/media_url_inventory.csv",
            ["image_cache_references"] = "analysis/image_cache_references.csv",
            ["suite_tv_liberator_confirmed"] =
                "analysis/Suite-TV-Liberator-confirmed.zip",
            ["suite_tv_liberator_estimated_progress"] =
                "analysis/Suite-TV-Liberator-estimated-progress.zip",
            ["markdown_report"] = "analysis/TVTime-Recovered-Data.md",
            ["html_report"] = "analysis/TVTime-Recovered-Data.html",
        };

    internal static long MaximumBytesFor(string identifier) => identifier switch
    {
        "extraction_run_state" => MaximumStateBytes,
        "extraction_inventory" => MaximumInventoryBytes,
        "extraction_summary" or "analysis_summary" => MaximumSummaryBytes,
        "extraction_domains" => MaximumDomainsBytes,
        _ => MaximumGeneratedArtifactBytes,
    };
}
