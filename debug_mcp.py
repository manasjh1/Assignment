# debug_mcp.py - Debug test to see raw MCP server output

import asyncio
import sys
import json
import subprocess

async def debug_mcp_server():
    print("🔍 Testing DuckDuckGo MCP server directly...")
    
    try:
        # Test with direct subprocess communication (simpler approach)
        print("📡 Starting MCP server process...")
        
        # Create MCP requests
        init_request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "debug-client", "version": "1.0.0"}
            }
        }
        
        search_request = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "search",
                "arguments": {
                    "query": "python programming",
                    "max_results": 3
                }
            }
        }
        
        # Start MCP server
        process = await asyncio.create_subprocess_exec(
            sys.executable, "-m", "duckduckgo_mcp_server",
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        # Send requests
        init_data = json.dumps(init_request) + "\n"
        search_data = json.dumps(search_request) + "\n"
        
        print("📤 Sending initialization request...")
        process.stdin.write(init_data.encode())
        await process.stdin.drain()
        
        print("📤 Sending search request...")
        process.stdin.write(search_data.encode())
        await process.stdin.drain()
        
        # Close stdin and wait for response
        process.stdin.close()
        
        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=15.0
            )
        except asyncio.TimeoutError:
            print("⚠️ Timeout waiting for MCP server response")
            process.terminate()
            return
        
        print(f"\n📥 Process return code: {process.returncode}")
        
        if stderr:
            print(f"\n⚠️ Stderr: {stderr.decode()}")
        
        if stdout:
            print(f"\n📄 Raw stdout ({len(stdout)} bytes):")
            raw_output = stdout.decode()
            print(raw_output)
            
            # Try to parse JSON responses
            lines = raw_output.strip().split('\n')
            print(f"\n🔍 Parsing {len(lines)} response lines:")
            
            for i, line in enumerate(lines):
                if line.strip():
                    try:
                        response = json.loads(line)
                        print(f"\nResponse {i}:")
                        print(f"  ID: {response.get('id')}")
                        print(f"  Method: {response.get('method', 'N/A')}")
                        
                        if 'result' in response:
                            result = response['result']
                            print(f"  Result type: {type(result)}")
                            if isinstance(result, dict) and 'content' in result:
                                print(f"  Content items: {len(result['content'])}")
                                for j, content in enumerate(result['content']):
                                    if hasattr(content, 'text'):
                                        print(f"    Content {j}: {content.text[:100]}...")
                                    else:
                                        print(f"    Content {j}: {str(content)[:100]}...")
                        
                        if 'error' in response:
                            print(f"  Error: {response['error']}")
                            
                    except json.JSONDecodeError as e:
                        print(f"  Line {i}: Not valid JSON - {e}")
                        print(f"  Raw: {line[:100]}...")
        else:
            print("\n❌ No stdout from MCP server")
        
        print("\n✅ Debug test completed!")
        
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(debug_mcp_server())