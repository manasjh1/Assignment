# image_service.py - Service for Flux Image Generation MCP with Clipdrop Fallback

import logging
import os
import base64
import json
import httpx
from typing import Dict, Any
from urllib.parse import urlencode

# Import MCP client components
try:
    from mcp import ClientSession
    from mcp.client.streamable_http import streamablehttp_client
    MCP_AVAILABLE = True
except ImportError:
    MCP_AVAILABLE = False

from config import FLUX_MCP_SERVER_URL, FLUX_MCP_API_KEY, CLIPDROP_API_KEY

logger = logging.getLogger(__name__)

class FluxImageGenService:
    """Flux Image Generation using MCP with Clipdrop Fallback"""
    
    def __init__(self):
        self.base_url = FLUX_MCP_SERVER_URL
        self.api_key = FLUX_MCP_API_KEY
        self.clipdrop_key = CLIPDROP_API_KEY
        self.clipdrop_url = "https://clipdrop-api.co/text-to-image/v1"
    
    async def generate_image(self, prompt: str, model: str = "flux", width: int = 1024, height: int = 1024) -> Dict[str, Any]:
        """Generate an image URL using the remote MCP server, falling back to Clipdrop"""
        
        # 1. Try Flux MCP Server
        if MCP_AVAILABLE:
            try:
                logger.info(f"Generating image via Flux MCP for: {prompt}")
                
                # Construct URL with auth
                params = {}
                if self.api_key:
                    params["api_key"] = self.api_key
                
                url = f"{self.base_url}"
                if params:
                    url = f"{url}?{urlencode(params)}"
                
                async with streamablehttp_client(url) as (read, write, _):
                    async with ClientSession(read, write) as session:
                        await session.initialize()
                        
                        # Call the generateImageUrl tool
                        result = await session.call_tool(
                            "generateImageUrl",
                            arguments={
                                "prompt": prompt,
                                "model": model,
                                "width": width,
                                "height": height,
                                "safe": True,
                                "enhance": True
                            }
                        )
                        
                        if result and result.content:
                            content_text = result.content[0].text
                            
                            # FIX: Parse the JSON string to get the actual URL
                            try:
                                data = json.loads(content_text)
                                
                                # --- ERROR CHECK ADDED HERE ---
                                # Check if the API returned an error object instead of success
                                if isinstance(data, dict) and ("error" in data or "message" in data):
                                    # If it looks like an error response, raise exception to trigger fallback
                                    error_msg = data.get("message") or data.get("error")
                                    if error_msg and "server" in str(error_msg).lower():
                                         raise Exception(f"MCP Server Error: {error_msg}")

                                # Extract 'imageUrl' from the dictionary, default to raw text if missing
                                final_url = data.get("imageUrl", content_text)
                            except json.JSONDecodeError:
                                # If it's not JSON, assume it's the raw URL
                                final_url = content_text
                                
                            return self._create_success_response(prompt, final_url, "Flux MCP")
                        else:
                            logger.warning("Flux MCP returned no content")

            except Exception as e:
                logger.error(f"Flux MCP generation failed: {str(e)}")
                # Proceed to fallback (The code continues below naturally)

        # 2. Fallback: Try Clipdrop API
        return await self._generate_with_clipdrop(prompt)

    async def _generate_with_clipdrop(self, prompt: str) -> Dict[str, Any]:
        """Fallback generation using Clipdrop API"""
        if not self.clipdrop_key:
            logger.warning("Clipdrop API key not configured, skipping fallback")
            return self._create_placeholder_response(prompt, "No providers available")

        try:
            logger.info(f"Attempting fallback generation via Clipdrop for: {prompt}")
            
            headers = { 'x-api-key': self.clipdrop_key }
            files = {
                'prompt': (None, prompt, 'text/plain')
            }

            async with httpx.AsyncClient() as client:
                response = await client.post(
                    self.clipdrop_url,
                    headers=headers,
                    files=files,
                    timeout=30.0
                )

            if response.status_code == 200:
                # Clipdrop returns raw bytes. Convert to base64 data URI
                image_bytes = response.content
                base64_image = base64.b64encode(image_bytes).decode('utf-8')
                data_uri = f"data:image/png;base64,{base64_image}"
                
                return self._create_success_response(prompt, data_uri, "Clipdrop API (Fallback)")
            else:
                error_msg = f"Clipdrop error {response.status_code}: {response.text}"
                logger.error(error_msg)
                return self._create_placeholder_response(prompt, error_msg)

        except Exception as e:
            logger.error(f"Clipdrop fallback failed: {str(e)}")
            return self._create_placeholder_response(prompt, str(e))

    def _create_success_response(self, prompt: str, image_url: str, provider: str) -> Dict[str, Any]:
        return {
            "image_url": image_url,
            "prompt": prompt,
            "status": "success",
            "provider": provider
        }

    def _create_error_response(self, prompt: str, error_message: str) -> Dict[str, Any]:
        return {
            "image_url": "",
            "prompt": prompt,
            "status": "error",
            "error": error_message,
            "provider": "None"
        }

    def _create_placeholder_response(self, prompt: str, error: str) -> Dict[str, Any]:
        """Final resort if all APIs fail"""
        logger.warning(f"Using placeholder image for: {prompt}. Last error: {error}")
        return {
            "image_url": f"https://placehold.co/1024x1024/png?text={prompt[:20]}...",
            "prompt": prompt,
            "status": "success",
            "provider": "Placeholder (All APIs Failed)",
            "error": f"Generation failed: {error}"
        }

image_service = FluxImageGenService()