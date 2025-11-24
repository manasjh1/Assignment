# find_mcp_server.py - Find the correct way to run DuckDuckGo MCP server

import sys
import os
import subprocess
import importlib.util

def find_mcp_server():
    print("🔍 Finding DuckDuckGo MCP server...")
    
    try:
        # Method 1: Try importing the package
        import duckduckgo_mcp_server
        package_path = os.path.dirname(duckduckgo_mcp_server.__file__)
        print(f"📦 Package location: {package_path}")
        
        # List files in package
        print("\n📁 Package contents:")
        for item in os.listdir(package_path):
            print(f"  - {item}")
        
        # Method 2: Look for common server file names
        server_files = [
            "server.py",
            "main.py", 
            "ddg_search_server.py",
            "__main__.py",
            "app.py"
        ]
        
        found_server = None
        for server_file in server_files:
            server_path = os.path.join(package_path, server_file)
            if os.path.exists(server_path):
                print(f"✅ Found server file: {server_file}")
                found_server = server_path
                break
        
        if found_server:
            print(f"\n🚀 Testing server: {found_server}")
            
            # Test running the server
            cmd = [sys.executable, found_server, "--help"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            
            print(f"Return code: {result.returncode}")
            if result.stdout:
                print(f"Stdout: {result.stdout}")
            if result.stderr:
                print(f"Stderr: {result.stderr}")
            
            return found_server
        else:
            print("❌ No server file found")
            
            # Method 3: Try to find entry points
            try:
                import pkg_resources
                for entry_point in pkg_resources.iter_entry_points():
                    if 'duckduckgo' in entry_point.name or 'mcp' in entry_point.name:
                        print(f"📍 Found entry point: {entry_point.name} -> {entry_point}")
            except:
                pass
        
        # Method 4: Try direct import and check for main functions
        print("\n🔍 Looking for main functions...")
        
        # Try to find the main server function
        for attr_name in dir(duckduckgo_mcp_server):
            attr = getattr(duckduckgo_mcp_server, attr_name)
            if callable(attr) and ('main' in attr_name.lower() or 'server' in attr_name.lower()):
                print(f"📌 Found callable: {attr_name}")
        
        return None
        
    except ImportError as e:
        print(f"❌ Cannot import duckduckgo_mcp_server: {e}")
        return None
    except Exception as e:
        print(f"❌ Error: {e}")
        return None

def test_alternative_approaches():
    print("\n🧪 Testing alternative approaches...")
    
    # Test 1: Try running as python -c
    print("\n1. Testing direct import approach:")
    test_script = '''
import sys
try:
    import duckduckgo_mcp_server
    print("✅ Package imported successfully")
    
    # Look for server or main functions
    attrs = [attr for attr in dir(duckduckgo_mcp_server) if not attr.startswith("_")]
    print("📋 Available attributes:", attrs)
    
    # Try to find a server function
    for attr_name in attrs:
        attr = getattr(duckduckgo_mcp_server, attr_name)
        if callable(attr):
            print(f"📞 Callable: {attr_name}")
            
except Exception as e:
    print(f"❌ Error: {e}")
    sys.exit(1)
'''
    
    result = subprocess.run([sys.executable, "-c", test_script], 
                          capture_output=True, text=True)
    print(result.stdout)
    if result.stderr:
        print("Stderr:", result.stderr)

if __name__ == "__main__":
    server_path = find_mcp_server()
    test_alternative_approaches()
    
    if server_path:
        print(f"\n✅ Use this command to run the server:")
        print(f"python {server_path}")
    else:
        print(f"\n💡 Try these approaches:")
        print(f"1. python -c 'import duckduckgo_mcp_server; duckduckgo_mcp_server.main()'")
        print(f"2. Check package documentation for correct usage")