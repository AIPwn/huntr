import logging
from typing import List, Union, Dict, Any
from pydantic import BaseModel, ValidationError
import anthropic
import os
import openai
import dotenv
import requests
import json
import time

dotenv.load_dotenv()

log = logging.getLogger(__name__)

class LLMError(Exception):
    """Base class for all LLM-related exceptions."""
    pass

class RateLimitError(LLMError):
    pass

class APIConnectionError(LLMError):
    pass

class APIStatusError(LLMError):
    def __init__(self, status_code: int, response: Dict[str, Any]):
        self.status_code = status_code
        self.response = response
        super().__init__(f"Received non-200 status code: {status_code}")

# Base LLM class to handle common functionality
class LLM:
    def __init__(self, system_prompt: str = "") -> None:
        self.system_prompt = system_prompt
        self.history: List[Dict[str, str]] = []
        self.prev_prompt: Union[str, None] = None
        self.prev_response: Union[str, None] = None
        self.prefill = None

    def _validate_response(self, response_text: str, response_model: BaseModel) -> BaseModel:
        try:
            if self.prefill:
                response_text = self.prefill + response_text
            return response_model.model_validate_json(response_text)
        except ValidationError as e:
            log.warning("[-] Response validation failed\n", exc_info=e)
            raise LLMError("Validation failed") from e

    def _add_to_history(self, role: str, content: str) -> None:
        self.history.append({"role": role, "content": content})

    def _handle_error(self, e: Exception, attempt: int) -> None:
        log.error(f"An error occurred on attempt {attempt}: {str(e)}", exc_info=e)
        raise e

    def _log_response(self, response: Dict[str, Any]) -> None:
        usage_info = response.usage.__dict__
        log.debug("Received chat response", extra={"usage": usage_info})

    def chat(self, user_prompt: str, response_model: BaseModel = None, max_tokens: int = 8192) -> Union[BaseModel, str]:
        self._add_to_history("user", user_prompt)
        messages = self.create_messages(user_prompt)
        response = self.send_message(messages, max_tokens, response_model)
        self._log_response(response)

        response_text = self.get_response(response)
        if response_model:
            response_text = self._validate_response(response_text, response_model) if response_model else response_text
        self._add_to_history("assistant", response_text)
        return response_text

class Claude(LLM):
    def __init__(self, model: str, base_url: str, system_prompt: str = "") -> None:
        super().__init__(system_prompt)
        # API key is retrieved from an environment variable by default
        self.client = anthropic.Anthropic(max_retries=3, base_url=base_url)
        self.model = model

    def create_messages(self, user_prompt: str) -> List[Dict[str, str]]:
        if "Provide a very concise summary of the README.md content" in user_prompt:
            messages = [{"role": "user", "content": user_prompt}]
        else:
            self.prefill = "{    \"scratchpad\": \"1."
            messages = [{"role": "user", "content": user_prompt}, 
                        {"role": "assistant", "content": self.prefill}]
        return messages

    def send_message(self, messages: List[Dict[str, str]], max_tokens: int, response_model: BaseModel) -> Dict[str, Any]:
        try:
            # response_model is not used here, only in ChatGPT
            return self.client.messages.create(
                model=self.model,
                max_tokens=max_tokens,
                system=self.system_prompt,
                messages=messages
            )
        except anthropic.APIConnectionError as e:
            raise APIConnectionError("Server could not be reached") from e
        except anthropic.RateLimitError as e:
            raise RateLimitError("Request was rate-limited") from e
        except anthropic.APIStatusError as e:
            raise APIStatusError(e.status_code, e.response) from e

    def get_response(self, response: Dict[str, Any]) -> str:
        return response.content[0].text.replace('\n', '')


class ChatGPT(LLM):
    def __init__(self, model: str, base_url: str, system_prompt: str = "") -> None:
        super().__init__(system_prompt)
        self.client = openai.OpenAI(api_key=os.getenv("OPENAI_API_KEY"), base_url=base_url)
        self.model = model

    def create_messages(self, user_prompt: str) -> List[Dict[str, str]]:
        messages = [{"role": "system", "content": self.system_prompt}, 
                    {"role": "user", "content": user_prompt}]
        return messages

    def send_message(self, messages: List[Dict[str, str]], max_tokens: int, response_model=None) -> Dict[str, Any]:
        try:
            params = {
                "model": self.model,
                "messages": messages,
                "max_tokens": max_tokens,
            }

            # Add response format configuration if a model is provided
            if response_model:
                params["response_format"] = {
                    "type": "json_object"
                }

            return self.client.chat.completions.create(**params)
        except openai.APIConnectionError as e:
            raise APIConnectionError("The server could not be reached") from e
        except openai.RateLimitError as e:
            raise RateLimitError("Request was rate-limited; consider backing off") from e
        except openai.APIStatusError as e:
            raise APIStatusError(e.status_code, e.response) from e
        except Exception as e:
            raise LLMError(f"An unexpected error occurred: {str(e)}") from e

    def get_response(self, response: Dict[str, Any]) -> str:
        response = response.choices[0].message.content
        return response


class Ollama(LLM):
    def __init__(self, model: str, base_url: str, system_prompt: str = "") -> None:
        super().__init__(system_prompt)
        self.api_url = base_url
        self.model = model

    def create_messages(self, user_prompt: str) -> str:
        return user_prompt

    def send_message(self, user_prompt: str, max_tokens: int, response_model: BaseModel) -> Dict[str, Any]:
        payload = {
            "model": self.model,
            "prompt": user_prompt,
            "options": {
            "temperature": 1,
            "system": self.system_prompt,
            }
            ,"stream":False,
        }

        try:
            response = requests.post(self.api_url, json=payload)
            return response
        except requests.exceptions.RequestException as e:
            if e.response.status_code == 429:
                raise RateLimitError("Request was rate-limited") from e
            elif e.response.status_code >= 500:
                raise APIConnectionError("Server could not be reached") from e
            else:
                raise APIStatusError(e.response.status_code, e.response.json()) from e

    def get_response(self, response: Dict[str, Any]) -> str:
        response = response.json()['response']
        return response

    def _log_response(self, response: Dict[str, Any]) -> None:
        log.debug("Received chat response", extra={"usage": "Ollama"})


class Deepseek(LLM):
    def __init__(self, model: str, base_url: str, system_prompt: str = "") -> None:
        super().__init__(system_prompt)
        self.api_key = os.getenv("DEEPSEEK_API_KEY")
        if not self.api_key:
            raise LLMError("DEEPSEEK_API_KEY environment variable not set")
        log.debug("Initializing Deepseek client, API URL: {}".format(base_url))
        self.client = openai.OpenAI(
            api_key=self.api_key,
            base_url=base_url,
            timeout=120.0  # Increase timeout to 120 seconds
        )
        self.model = model
        self.max_retries = 3

    def create_messages(self, user_prompt: str) -> List[Dict[str, str]]:
        log.debug("Creating messages, prompt length: {}".format(len(user_prompt)))
        # Add a clear prompt to tell the model to return a specific JSON format
        structured_prompt = f"""
{user_prompt}

Please return the result in the following JSON format:
{{
  "scratchpad": "Detailed analysis process",
  "analysis": "Final analysis result",
  "poc": "Proof of concept code for exploitation (if applicable)",
  "confidence_score": An integer between 0-10 representing confidence level,
  "vulnerability_types": ["List of vulnerability types, such as LFI, RCE, SSRF, etc."],
  "context_code": [
    {{
      "name": "Function or class name",
      "reason": "Brief reason why this code is needed for analysis",
      "code_line": "The single line of code where this context object is referenced"
    }}
  ]
}}
"""
        messages = [
            {"role": "system", "content": self.system_prompt},
            {"role": "user", "content": structured_prompt}
        ]
        return messages

    def send_message(self, messages: List[Dict[str, str]], max_tokens: int, response_model: BaseModel = None) -> Dict[str, Any]:
        retries = 0
        while retries <= self.max_retries:
            try:
                log.debug(f"Sending request to Deepseek API (attempt {retries+1}/{self.max_retries+1})")
                params = {
                    "model": self.model,
                    "messages": messages,
                    "max_tokens": max_tokens,
                }

                if response_model:
                    params["response_format"] = {
                        "type": "json_object"
                    }

                response = self.client.chat.completions.create(**params)
                log.debug("Successfully received Deepseek API response")
                return response
            except openai.APIConnectionError as e:
                retries += 1
                retry_wait = 2 ** retries  # Exponential backoff
                error_msg = str(e)
                
                if "timeout" in error_msg.lower() and retries <= self.max_retries:
                    log.warning(f"Deepseek API timeout (attempt {retries}/{self.max_retries+1}). Retrying in {retry_wait} seconds...")
                    time.sleep(retry_wait)
                    continue
                
                log.error(f"Deepseek API connection error: {error_msg}")
                raise APIConnectionError("Could not connect to server") from e
            except openai.RateLimitError as e:
                log.error("Deepseek API rate limit: {}".format(str(e)))
                raise RateLimitError("Request was rate limited") from e
            except openai.APIStatusError as e:
                log.error("Deepseek API status error, status code: {}, error: {}".format(e.status_code, str(e)))
                raise APIStatusError(e.status_code, e.response) from e
            except Exception as e:
                log.error("Deepseek API unknown error: {}".format(str(e)))
                raise LLMError(f"An unexpected error occurred: {str(e)}") from e

    def get_response(self, response: Dict[str, Any]) -> str:
        try:
            content = response.choices[0].message.content
            return content
        except Exception as e:
            log.error("Error parsing response: {}".format(str(e)))
            raise LLMError(f"Error parsing response: {str(e)}") from e

    def _log_response(self, response: Dict[str, Any]) -> None:
        try:
            usage_info = response.usage.__dict__
            log.debug("Received chat response", extra={"usage": usage_info})
        except Exception as e:
            log.error("Error logging response usage: {}".format(str(e)))

    def _validate_response(self, response_text: str, response_model: BaseModel) -> BaseModel:
        """
        Custom validation method to convert Deepseek API JSON format to our Response model format
        """
        # Define vulnerability type mapping 
        vuln_type_map = {
            # Standard mapping
            "lfi": "LFI",
            "rce": "RCE", 
            "ssrf": "SSRF",
            "afo": "AFO",
            "sqli": "SQLI", 
            "sql injection": "SQLI",
            "xss": "XSS",
            "cross-site scripting": "XSS",
            "idor": "IDOR",
            
            # Extended mapping
            "command injection": "CMDI",
            "arbitrary file deletion": "AFD",
            "arbitrary file write": "AFW",
            "arbitrary file read": "AFR",
            "path traversal": "PATH",
            "directory traversal": "PATH",
            "csrf": "CSRF",
            "cross-site request forgery": "CSRF",
            "xxe": "XXE",
            "xml external entity": "XXE",
            "insecure deserialization": "DESERIALIZATION",
            "deserialization": "DESERIALIZATION",
            "broken authentication": "BROKEN_AUTH",
            "information leak": "INFO_LEAK",
            "information disclosure": "INFO_LEAK",
            "insecure configuration": "INSECURE_CONFIG",
            "open redirect": "OPEN_REDIRECT",
        }
        
        # Helper function to map vulnerability types
        def map_vuln_type(vuln_type: str) -> str:
            # Convert to lowercase for case-insensitive matching
            vuln_lower = vuln_type.lower()
            
            # Try direct mapping
            if vuln_lower in vuln_type_map:
                return vuln_type_map[vuln_lower]
            
            # Try partial matching for longer descriptions
            for key, value in vuln_type_map.items():
                if key in vuln_lower:
                    return value
                
            # Default to UNKNOWN for unrecognized types
            log.warning(f"Unrecognized vulnerability type: {vuln_type}")
            return "UNKNOWN"
        
        try:
            # First try direct validation
            log.debug("Attempting direct validation of response")
            if self.prefill:
                response_text = self.prefill + response_text
            return response_model.model_validate_json(response_text)
        except Exception as e:
            log.warning("Direct validation failed, attempting format conversion...")
            try:
                # Try to parse response text as JSON
                data = json.loads(response_text)
                log.debug("Successfully parsed JSON response")
                
                # If response contains vulnerabilities array, convert to our format
                if 'vulnerabilities' in data:
                    log.debug("Detected vulnerabilities field, converting format")
                    vulns = data.get('vulnerabilities', [])
                    
                    # Create a new data structure that conforms to our model
                    converted_data = {
                        "scratchpad": data.get('analysis', "Analysis process not provided"),
                        "analysis": data.get('summary', "Analysis result not provided"),
                        "poc": data.get('poc', ""),
                        "confidence_score": data.get('confidence', 5),
                        "vulnerability_types": [map_vuln_type(v.get('type', 'UNKNOWN')) for v in vulns],
                        "context_code": []
                    }
                    
                    # Add context code to the result
                    if 'context' in data:
                        for ctx in data.get('context', []):
                            converted_data["context_code"].append({
                                "name": ctx.get('name', "Unknown"),
                                "reason": ctx.get('reason', "Reason not provided"),
                                "code_line": ctx.get('code', "Code not provided")
                            })
                    
                    # Serialize back to JSON string
                    converted_json = json.dumps(converted_data)
                    
                    # Validate using the converted JSON
                    return response_model.model_validate_json(converted_json)
                else:
                    # If response has vulnerability_types field, map the values to valid enum values
                    if 'vulnerability_types' in data and isinstance(data['vulnerability_types'], list):
                        data['vulnerability_types'] = [map_vuln_type(v) for v in data['vulnerability_types']]
                    
                    # If response contains required fields but format might not be exactly correct
                    required_fields = ["scratchpad", "analysis", "poc", "confidence_score", "vulnerability_types", "context_code"]
                    for field in required_fields:
                        if field not in data:
                            data[field] = "" if field != "confidence_score" and field != "vulnerability_types" and field != "context_code" else \
                                          5 if field == "confidence_score" else \
                                          [] if field == "vulnerability_types" or field == "context_code" else ""
                    
                    # Serialize back to JSON string
                    converted_json = json.dumps(data)
                    
                    # Validate using the fixed JSON
                    return response_model.model_validate_json(converted_json)
            except Exception as inner_e:
                log.error("Format conversion failed: {}".format(str(inner_e)))
                
                # Create a default response with UNKNOWN vulnerability type (which is now a valid enum value)
                default_response = {
                    "scratchpad": "API returned format that could not be parsed: " + response_text[:200] + "...",
                    "analysis": "The data format returned by the API is incorrect and could not be analyzed.",
                    "poc": "",
                    "confidence_score": 0,
                    "vulnerability_types": ["UNKNOWN"],
                    "context_code": []
                }
                
                # Serialize to JSON string
                default_json = json.dumps(default_response)
                
                # Validate using the default response
                return response_model.model_validate_json(default_json)

