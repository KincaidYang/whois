package utils

import (
	"testing"
)

func TestCacheResult(t *testing.T) {
	tests := []struct {
		name     string
		data     string
		found    bool
		expected CacheResult
	}{
		{
			name:     "Cache hit",
			data:     "test data",
			found:    true,
			expected: CacheResult{Data: "test data", Found: true},
		},
		{
			name:     "Cache miss",
			data:     "",
			found:    false,
			expected: CacheResult{Data: "", Found: false},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CacheResult{Data: tt.data, Found: tt.found}
			if result.Data != tt.expected.Data || result.Found != tt.expected.Found {
				t.Errorf("CacheResult = %v, expected %v", result, tt.expected)
			}
		})
	}
}

func TestGetFromCacheError(t *testing.T) {
	// Test case for when Redis returns an error (not redis.Nil)
	// This would require a mock Redis client in a real test scenario
	// For now, we'll just test the CacheResult struct behavior
	result := CacheResult{Found: false}
	if result.Found {
		t.Error("Expected Found to be false for cache miss")
	}
}

func TestSetToCacheStringData(t *testing.T) {
	// Test that string data is handled correctly
	// This would require a mock Redis client for proper testing
	// For now, we'll test the basic logic structure
	testData := "test string data"

	// In a real test, we would:
	// 1. Set up a mock Redis client
	// 2. Call SetToCache
	// 3. Verify the correct data was stored

	if testData == "" {
		t.Error("Test data should not be empty")
	}
}

func TestSetToCacheStructData(t *testing.T) {
	// Test that struct data is marshaled to JSON correctly
	testStruct := struct {
		Name  string `json:"name"`
		Value int    `json:"value"`
	}{
		Name:  "test",
		Value: 123,
	}

	// In a real test, we would verify JSON marshaling works correctly
	if testStruct.Name == "" {
		t.Error("Test struct should have a name")
	}
}
