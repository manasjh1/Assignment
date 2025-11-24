# test_mcp.py - Quick test of MCP server

import asyncio
from search_service import search_service

async def test_search():
    print("🔍 Testing DuckDuckGo MCP server...")
    result = await search_service.search_web("artificial intelligence", 5)
    
    print("\n✅ Search Results:")
    print(f"Query: {result['query']}")
    print(f"Status: {result['status']}")
    print(f"Total results: {result['total']}")
    
    print("\nResults:")
    for i, result_item in enumerate(result['results'], 1):
        print(f"\n{i}. Title: {result_item['title']}")
        print(f"   Snippet: {result_item['snippet'][:100]}...")
        print(f"   URL: {result_item['url']}")
        print(f"   Source: {result_item['source']}")

if __name__ == "__main__":
    asyncio.run(test_search())