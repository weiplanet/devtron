package cache

import (
	"fmt"
	"time"

	"github.com/devtron-labs/devtron/pkg/common"
)

// Cache provides strongly types methods to store and retrieve values from shared cache
type Cache struct {
	client CacheClient
}

func (c *Cache) SetItem(key string, item interface{}, expiration time.Duration, delete bool) error {
	key = fmt.Sprintf("%s|%s", key, common.CacheVersion)
	if delete {
		return c.client.Delete(key)
	} else {
		if item == nil {
			return fmt.Errorf("cannot set item to nil for key %s", key)
		}
		return c.client.Set(&Item{Object: item, Key: key, Expiration: expiration})
	}
}

func (c *Cache) GetItem(key string, item interface{}) error {
	if item == nil {
		return fmt.Errorf("cannot get item into a nil for key %s", key)
	}
	key = fmt.Sprintf("%s|%s", key, common.CacheVersion)
	return c.client.Get(key, item)
}
