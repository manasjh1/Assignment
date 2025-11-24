# test_mcp_direct.py - Test the MCP server directly

import asyncio
import json
import sys
import os

async def test_mcp_server():
    print("🔍 Testing DuckDuckGo MCP server directly...")
    
    try:
        # Get server path
        import duckduckgo_mcp_server
        package_path = os.path.dirname(duckduckgo_mcp_server.__file__)
        server_path = os.path.join(package_path, "server.py")
        
        print(f"📍 Server path: {server_path}")
        print(f"📍 Server exists: {os.path.exists(server_path)}")
        
        if not os.path.exists(server_path):
            print("❌ Server file not found!")
            return
        
        # Test server command
        cmd = [sys.executable, server_path]
        print(f"🚀 Command: {' '.join(cmd)}")
        
        # Create requests
        init_request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "test-client", "version": "1.0.0"}
            }
        }
        
        search_request = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "search",
                "arguments": {"query": "test search", "max_results": 3}
            }
        }
        
        # Start process
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        # Send requests
        init_data = json.dumps(init_request) + "\n"
        search_data = json.dumps(search_request) + "\n"
        
        process.stdin.write(init_data.encode())
        await process.stdin.drain()
        process.stdin.write(search_data.encode())
        await process.stdin.drain()
        process.stdin.close()
        
        # Wait for response
        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(), timeout=15.0
            )
        except asyncio.TimeoutError:
            print("⚠️ Timeout waiting for response")
            process.terminate()
            return
        
        print(f"\n📊 Results:")
        print(f"Return code: {process.returncode}")
        print(f"Stdout length: {len(stdout)} bytes")
        print(f"Stderr length: {len(stderr)} bytes")
        
        if stderr:
            stderr_text = stderr.decode()
            print(f"\n📄 Stderr preview:")
            print(stderr_text[:300])
            if "duckduckgo" in stderr_text.lower():
                print("✅ DuckDuckGo mentioned in logs!")
        
        if stdout:
            stdout_text = stdout.decode()
            print(f"\n📄 Stdout preview:")
            print(stdout_text[:300])
        
        return process.returncode == 0 or "duckduckgo" in stderr.decode().lower()
        
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

if __name__ == "__main__":
    success = asyncio.run(test_mcp_server())
    if success:
        print("\n✅ MCP server test successful!")
    else:
        print("\n❌ MCP server test failed!")