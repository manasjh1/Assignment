# search_service.py - Working DuckDuckGo MCP Server integration

import asyncio
import json
import sys
import logging
import os
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

class DuckDuckGoMCPService:
    """DuckDuckGo search using Model Context Protocol (MCP)"""
    
    def __init__(self):
        self.server_cmd = None
        self._initialize_server()
    
    def _initialize_server(self):
        """Initialize the MCP server command"""
        try:
            import duckduckgo_mcp_server
            package_path = os.path.dirname(duckduckgo_mcp_server.__file__)
            server_path = os.path.join(package_path, "server.py")
            
            if os.path.exists(server_path):
                self.server_cmd = [sys.executable, server_path]
                logger.info(f"DuckDuckGo MCP server initialized")
            else:
                logger.error("DuckDuckGo MCP server.py not found")
                
        except ImportError as e:
            logger.error(f"DuckDuckGo MCP server package not installed: {e}")
    
    async def search(self, query: str, max_results: int = 10) -> Dict[str, Any]:
        """Perform web search using DuckDuckGo MCP server"""
        if not self.server_cmd:
            return self._create_error_response(query, "MCP server not available")
        
        try:
            logger.info(f"MCP search for: {query}")
            
            # MCP protocol requests
            init_request = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": "fastapi-search", "version": "1.0.0"}
                }
            }
            
            search_request = {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": "search",
                    "arguments": {"query": query.strip(), "max_results": max_results}
                }
            }
            
            # Execute MCP request
            result = await self._execute_mcp_request(init_request, search_request)
            
            if result["success"]:
                # Check if we got real results
                if "results" in result:
                    return self._create_success_response(query, max_results, result["results"])
                else:
                    return self._create_success_response(query, max_results)
            else:
                return self._create_error_response(query, result["error"])
                
        except Exception as e:
            logger.error(f"Search failed: {str(e)}")
            return self._create_error_response(query, f"Search error: {str(e)}")
    
    async def _execute_mcp_request(self, init_request: dict, search_request: dict) -> Dict[str, Any]:
        """Execute the MCP server request (Windows-compatible)"""
        try:
            logger.info(f"Starting MCP server with command: {' '.join(self.server_cmd)}")
            
            # Use synchronous subprocess for Windows compatibility
            import subprocess
            import time
            
            logger.info("Executing MCP server with keep-alive communication...")
            
            # Start the process but keep it alive
            process = subprocess.Popen(
                self.server_cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,  # Use text mode for easier handling
                bufsize=0   # Unbuffered for immediate response
            )
            
            # Send initialization request
            init_data = json.dumps(init_request) + "\n"
            logger.info("Sending initialization request...")
            process.stdin.write(init_data)
            process.stdin.flush()
            
            # Wait briefly for initialization
            time.sleep(0.5)
            
            # Send search request  
            search_data = json.dumps(search_request) + "\n"
            logger.info("Sending search request...")
            process.stdin.write(search_data)
            process.stdin.flush()
            
            # Keep the process alive longer to get all responses
            logger.info("Waiting for search results...")
            time.sleep(5)  # Wait longer for search to complete
            
            # Now close stdin
            process.stdin.close()
            
            # Read all available output
            try:
                stdout, stderr = process.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                logger.error("MCP server request timed out after search")
                process.kill()
                stdout, stderr = process.communicate()
                return {"success": False, "error": "Search timeout"}
            
            
            logger.info(f"MCP server completed. Return code: {process.returncode}")
            logger.info(f"Stdout length: {len(stdout)} bytes, Stderr length: {len(stderr)} bytes")
            
            # Check results - no need to decode in text mode
            success_indicators = []
            
            if stderr:
                # stderr is already a string in text mode
                if "duckduckgo.com" in stderr.lower():
                    success_indicators.append("DuckDuckGo contacted")
                    logger.info("✅ MCP server successfully contacted DuckDuckGo")
                if "CallToolRequest" in stderr:
                    success_indicators.append("Tool request processed")
                    logger.info("✅ MCP server processed search request")
            
            if stdout:
                # stdout is already a string in text mode
                if len(stdout) > 50:  # Meaningful response
                    success_indicators.append("Got response data")
                    logger.info(f"✅ MCP server returned {len(stdout)} bytes of data")
            
            # If we have any success indicators, parse real results if available
            if success_indicators:
                logger.info(f"✅ MCP search successful: {', '.join(success_indicators)}")
                
                # Try to parse actual search results from stdout
                real_results = []
                if stdout:
                    logger.info(f"🔍 DEBUG - Full stdout content:")
                    logger.info(f"Raw stdout: {repr(stdout[:500])}...")  # Show first 500 chars
                    
                    # Split into lines and examine each JSON response
                    lines = stdout.strip().split('\n')
                    logger.info(f"📋 Total lines: {len(lines)}")
                    for i, line in enumerate(lines):
                        if line.strip():
                            logger.info(f"📋 Line {i}: {line[:100]}...")
                            try:
                                response = json.loads(line)
                                logger.info(f"📊 Parsed JSON - ID: {response.get('id')}, Keys: {list(response.keys())}")
                                if "result" in response:
                                    logger.info(f"📄 Result content keys: {list(response['result'].keys())}")
                            except:
                                logger.info(f"❌ Not JSON: {line[:50]}")
                    
                    real_results = self._parse_mcp_output(stdout, init_request, search_request)
                
                if real_results:
                    logger.info(f"✅ Parsed {len(real_results)} real search results")
                    return {"success": True, "data": "Real search results", "results": real_results}
                else:
                    logger.warning("❌ No real results parsed - check debug output above")
                    return {"success": False, "error": "Could not parse real search results from MCP output"}
            else:
                logger.warning("❌ No success indicators found")
                # Log more details for debugging
                if stderr:
                    logger.info(f"Stderr preview: {stderr[:200]}")
                if stdout:
                    logger.info(f"Stdout preview: {stdout[:200]}")
                return {"success": False, "error": f"No success indicators (rc: {process.returncode})"}
            
        except subprocess.TimeoutExpired:
            logger.error("MCP server request timed out")
            return {"success": False, "error": "Request timeout"}
        except Exception as e:
            import traceback
            error_msg = f"MCP server execution failed: {str(e)}"
            logger.error(error_msg)
            logger.error(f"Full traceback: {traceback.format_exc()}")
            return {"success": False, "error": error_msg}
    
    def _parse_mcp_output(self, stdout_text: str, init_request: dict, search_request: dict) -> List[Dict[str, Any]]:
        """Parse actual search results from MCP server stdout - including HTML content"""
        results = []
        
        # Extract query from search request
        query = search_request.get("params", {}).get("arguments", {}).get("query", "search")
        
        try:
            # The stdout contains JSON-RPC responses separated by newlines
            lines = stdout_text.strip().split('\n')
            
            for line in lines:
                if line.strip():
                    try:
                        response = json.loads(line)
                        
                        # Look for the search tool response (id=2)
                        if (response.get("id") == 2 and 
                            "result" in response and 
                            "content" in response["result"]):
                            
                            content_list = response["result"]["content"]
                            
                            for content_item in content_list:
                                if isinstance(content_item, dict):
                                    content_type = content_item.get("type", "")
                                    content_text = content_item.get("text", "")
                                    
                                    # Check if content contains HTML
                                    if content_text and ("<html" in content_text.lower() or "<div" in content_text.lower() or "<!doctype" in content_text.lower()):
                                        logger.info("🔍 Found HTML content - parsing with Beautiful Soup")
                                        html_results = self._parse_html_content(content_text, query)
                                        results.extend(html_results)
                                    
                                    elif content_text:
                                        # Parse as text content
                                        text_results = self._parse_search_results_text(content_text, query)
                                        results.extend(text_results)
                        
                        # Also check for HTML in notifications or other fields
                        elif response.get("method") == "notifications/message":
                            params = response.get("params", {})
                            data = params.get("data", "")
                            if data and ("<html" in data.lower() or "<div" in data.lower()):
                                logger.info("🔍 Found HTML in notification - parsing with Beautiful Soup")
                                html_results = self._parse_html_content(data, query)
                                results.extend(html_results)
                                        
                    except json.JSONDecodeError:
                        # Check if the line itself contains HTML
                        if "<html" in line.lower() or "<div" in line.lower():
                            logger.info("🔍 Found raw HTML line - parsing with Beautiful Soup")
                            html_results = self._parse_html_content(line, query)
                            results.extend(html_results)
                        continue
                        
        except Exception as e:
            logger.error(f"Error parsing MCP output: {e}")
        
        return results[:5]  # Return up to 5 results
    
    def _parse_html_content(self, html_content: str, query: str) -> List[Dict[str, Any]]:
        """Parse search results from HTML content using Beautiful Soup"""
        results = []
        
        try:
            from bs4 import BeautifulSoup
            
            logger.info(f"🔍 Parsing HTML content ({len(html_content)} chars)")
            soup = BeautifulSoup(html_content, 'html.parser')
            
            # Strategy 1: Look for common DuckDuckGo result patterns
            search_results = []
            
            # DuckDuckGo typically uses these classes/elements for results
            result_selectors = [
                '.result',
                '.result__body',
                '.web-result', 
                '.result-snippet',
                'div[data-testid="result"]',
                '.result-title',
                'article',
                '.search-result'
            ]
            
            for selector in result_selectors:
                found_results = soup.select(selector)
                if found_results:
                    logger.info(f"✅ Found {len(found_results)} results using selector: {selector}")
                    search_results = found_results
                    break
            
            # Strategy 2: If no specific result containers, look for link patterns
            if not search_results:
                # Look for groups of links that might be search results
                links = soup.find_all('a', href=True)
                title_elements = soup.find_all(['h1', 'h2', 'h3', 'h4'])
                
                logger.info(f"🔍 Found {len(links)} links and {len(title_elements)} titles")
                
                # Group nearby elements as potential results
                for i, link in enumerate(links[:10]):  # Check first 10 links
                    href = link.get('href', '')
                    text = link.get_text(strip=True)
                    
                    if (href.startswith('http') and 
                        len(text) > 10 and 
                        'duckduckgo.com' not in href):
                        
                        # Look for description near this link
                        parent = link.parent
                        snippet = ""
                        if parent:
                            snippet = parent.get_text(strip=True)[:200]
                        
                        results.append({
                            "title": text[:100],
                            "snippet": snippet if snippet else f"Search result for: {query}",
                            "url": href,
                            "source": "DuckDuckGo"
                        })
            
            # Strategy 3: Parse structured search results
            for result_elem in search_results:
                try:
                    title = ""
                    snippet = ""
                    url = ""
                    
                    # Extract title
                    title_elem = result_elem.find(['h1', 'h2', 'h3', 'h4', 'a'])
                    if title_elem:
                        title = title_elem.get_text(strip=True)
                    
                    # Extract URL
                    link_elem = result_elem.find('a', href=True)
                    if link_elem:
                        url = link_elem.get('href', '')
                    
                    # Extract snippet/description
                    snippet_elem = result_elem.find(['p', 'span', 'div'])
                    if snippet_elem:
                        snippet = snippet_elem.get_text(strip=True)[:300]
                    
                    if title and len(title) > 3:
                        results.append({
                            "title": title[:150],
                            "snippet": snippet if snippet else f"Search result for: {query}",
                            "url": url if url.startswith('http') else f"https://duckduckgo.com/?q={query.replace(' ', '+')}",
                            "source": "DuckDuckGo"
                        })
                        
                except Exception as e:
                    logger.error(f"Error parsing individual result: {e}")
                    continue
            
            logger.info(f"✅ Extracted {len(results)} results from HTML")
                        
        except ImportError:
            logger.error("❌ Beautiful Soup not installed - install with: pip install beautifulsoup4")
        except Exception as e:
            logger.error(f"Error parsing HTML content: {e}")
        
        return results
    
    def _parse_search_results_text(self, text: str, query: str) -> List[Dict[str, Any]]:
        """Parse search results from the text content returned by DuckDuckGo MCP"""
        results = []
        
        try:
            logger.info(f"🔍 Parsing search text: {text[:200]}...")
            
            # Split by lines and look for numbered results
            lines = text.split('\n')
            current_result = {}
            
            for line in lines:
                line = line.strip()
                
                # Skip empty lines
                if not line:
                    continue
                
                # Look for numbered results (1. Title, 2. Title, etc.)
                if (line.startswith(tuple('123456789')) and '. ' in line):
                    
                    # Save previous result if exists
                    if current_result and current_result.get('title'):
                        results.append(current_result)
                    
                    # Extract title (remove number prefix)
                    title = line.split('. ', 1)[1] if '. ' in line else line
                    current_result = {
                        "title": title.strip(),
                        "source": "DuckDuckGo"
                    }
                    logger.info(f"📌 Found result: {title[:50]}...")
                
                # Look for URLs (lines starting with http)
                elif line.startswith('http') and current_result:
                    current_result["url"] = line
                    logger.info(f"🔗 Found URL: {line[:50]}...")
                
                # Look for descriptions (lines that are sentences/descriptions)
                elif (len(line) > 30 and 
                      current_result and 
                      "snippet" not in current_result and
                      not line.startswith('http') and
                      not line.startswith(tuple('123456789'))):
                    
                    current_result["snippet"] = line[:300]
                    logger.info(f"📄 Found snippet: {line[:50]}...")
            
            # Add the last result
            if current_result and current_result.get('title'):
                results.append(current_result)
            
            # If no structured results found, try alternative parsing
            if not results:
                logger.info("🔄 No structured results found, trying alternative parsing...")
                
                # Look for lines that could be titles (longer lines without URLs)
                potential_titles = []
                for line in lines:
                    line = line.strip()
                    if (len(line) > 20 and 
                        len(line) < 150 and 
                        not line.startswith('http') and
                        not line.startswith('Found ') and
                        '?' in line or 'AI' in line or query.lower() in line.lower()):
                        potential_titles.append(line)
                
                # Create results from potential titles
                for i, title in enumerate(potential_titles[:5]):
                    results.append({
                        "title": title,
                        "snippet": f"Search result for '{query}' from DuckDuckGo",
                        "url": f"https://duckduckgo.com/?q={query.replace(' ', '+')}",
                        "source": "DuckDuckGo"
                    })
            
            # Ensure all results have required fields
            for result in results:
                if "url" not in result:
                    result["url"] = f"https://duckduckgo.com/?q={query.replace(' ', '+')}"
                if "snippet" not in result:
                    result["snippet"] = f"Search result for '{query}' from DuckDuckGo"
            
            logger.info(f"✅ Parsed {len(results)} results from search text")
                        
        except Exception as e:
            logger.error(f"Error parsing search results text: {e}")
        
        return results

    def _create_success_response(self, query: str, max_results: int, real_results: List[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Create successful search response with real results only"""
        
        # Only accept real results - no demo fallback
        if real_results:
            # Ensure all results have required fields
            for result in real_results:
                if "url" not in result:
                    result["url"] = f"https://duckduckgo.com/?q={query.replace(' ', '+')}"
                if "snippet" not in result:
                    result["snippet"] = "Search result from DuckDuckGo"
            
            return {
                "results": real_results[:max_results],
                "query": query.strip(),
                "total_results": len(real_results),
                "max_results": max_results,
                "status": "success",
                "search_engine": "DuckDuckGo",
                "protocol": "MCP"
            }
        
        # No demo fallback - return error if no real results
        return {
            "results": [],
            "query": query.strip(),
            "total_results": 0,
            "max_results": max_results,
            "status": "error",
            "error": "No real search results could be parsed from DuckDuckGo MCP response",
            "search_engine": "DuckDuckGo",
            "protocol": "MCP"
        }
    
    def _create_error_response(self, query: str, error_message: str) -> Dict[str, Any]:
        """Create error response"""
        return {
            "results": [],
            "query": query.strip(),
            "total_results": 0,
            "max_results": 0,
            "status": "error",
            "error": error_message,
            "search_engine": "DuckDuckGo",
            "protocol": "MCP"
        }

# Create singleton instance
search_service = DuckDuckGoMCPService()