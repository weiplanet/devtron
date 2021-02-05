package appstate

import (
	"time"

	cacheutil "github.com/devtron-labs/devtron/util/cache"
)

var ErrCacheMiss = cacheutil.ErrCacheMiss

const (
	clusterInfoCacheExpiration = 10 * time.Minute
)

type Cache struct {
	Cache                   *cacheutil.Cache
	appStateCacheExpiration time.Duration
}

func NewCache(cache *cacheutil.Cache, appStateCacheExpiration time.Duration) *Cache {
	return &Cache{cache, appStateCacheExpiration}
}

func (c *Cache) GetItem(key string, item interface{}) error {
	return c.Cache.GetItem(key, item)
}

func (c *Cache) SetItem(key string, item interface{}, expiration time.Duration, delete bool) error {
	return c.Cache.SetItem(key, item, expiration, delete)
}

