"""Advisory and metadata caching layer for depfence."""

from depfence.cache.advisory_cache import AdvisoryCache, CacheStats
from depfence.cache.download_cache import DownloadCache

__all__ = ["AdvisoryCache", "CacheStats", "DownloadCache"]
