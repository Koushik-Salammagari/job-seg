"""Define a custom Reasoning and Action agent.

Works with a chat model with tool calling support.
"""
import asyncio

from datetime import datetime, timezone
from typing import Dict, List, Literal, cast

from langchain_core.messages import AIMessage
from langchain_core.runnables import RunnableConfig
from langgraph.graph import StateGraph
from langgraph.prebuilt import ToolNode

from react_agent.configuration import Configuration
from react_agent.state import InputState, State
from react_agent.tools import TOOLS
from react_agent.utils import load_chat_model
from dotenv import load_dotenv
load_dotenv()

# Define the function that calls the model

import os
import base64

def load_json_secret(env_var: str, output_path: str):
    # print the current woerking directory
    print("Current working directory:", os.getcwd())
    print(f"Attempting to load environment variable: {env_var}")
    value = os.getenv(env_var)
    if not value:
        print(f"Error: {env_var} not found in environment.")
        raise ValueError(f"{env_var} not found in environment.")
    try:
        print(f"Decoding value for {env_var}")
        decoded = base64.b64decode(value).decode("utf-8")
    except Exception as e:
        print(f"Decoding failed for {env_var}, using fallback. Error: {e}")
        decoded = value  # fallback if it's plain text
    print(f"Writing decoded value to {output_path}")
    with open(output_path, "w") as f:
        f.write(decoded)
    print(f"Successfully wrote {env_var} to {output_path}")

# Original relative paths (commented out)
load_json_secret("GMAIL_TOKEN_JSON", "src/react_agent/token_gmail.json")
load_json_secret("SHEETS_TOKEN_JSON", "src/react_agent/token.json")
load_json_secret("GOOGLE_CREDENTIALS", "src/react_agent/credentials.json")



async def call_model(
    state: State, config: RunnableConfig
) -> Dict[str, List[AIMessage]]:
    """Call the LLM powering our "agent".

    This function prepares the prompt, initializes the model, and processes the response.

    Args:
        state (State): The current state of the conversation.
        config (RunnableConfig): Configuration for the model run.

    Returns:
        dict: A dictionary containing the model's response message.
    """
    configuration = Configuration.from_runnable_config(config)

    # Initialize the model with tool binding. Change the model or add more tools here.
    model = load_chat_model(configuration.model).bind_tools(TOOLS)

    # Format the system prompt. Customize this to change the agent's behavior.
    system_message = configuration.system_prompt.format(
        system_time=datetime.now(tz=timezone.utc).isoformat()
    )

    # Get the model's response
    response = cast(
        AIMessage,
        await model.ainvoke(
            [{"role": "system", "content": system_message}, *state.messages], config
        ),
    )

    # Handle the case when it's the last step and the model still wants to use a tool
    if state.is_last_step and response.tool_calls:
        return {
            "messages": [
                AIMessage(
                    id=response.id,
                    content="Sorry, I could not find an answer to your question in the specified number of steps.",
                )
            ]
        }

    # Return the model's response as a list to be added to existing messages
    return {"messages": [response]}


# Define a new graph

builder = StateGraph(State, input=InputState, config_schema=Configuration)

# Define the two nodes we will cycle between
builder.add_node(call_model)
builder.add_node("tools", ToolNode(TOOLS))

# Set the entrypoint as `call_model`
# This means that this node is the first one called
builder.add_edge("__start__", "call_model")


def route_model_output(state: State) -> Literal["__end__", "tools"]:
    """Determine the next node based on the model's output.

    This function checks if the model's last message contains tool calls.

    Args:
        state (State): The current state of the conversation.

    Returns:
        str: The name of the next node to call ("__end__" or "tools").
    """
    last_message = state.messages[-1]
    if not isinstance(last_message, AIMessage):
        raise ValueError(
            f"Expected AIMessage in output edges, but got {type(last_message).__name__}"
        )
    # If there is no tool call, then we finish
    if not last_message.tool_calls:
        return "__end__"
    # Otherwise we execute the requested actions
    return "tools"


# Add a conditional edge to determine the next step after `call_model`
builder.add_conditional_edges(
    "call_model",
    # After call_model finishes running, the next node(s) are scheduled
    # based on the output from route_model_output
    route_model_output,
)

# Add a normal edge from `tools` to `call_model`
# This creates a cycle: after using tools, we always return to the model
builder.add_edge("tools", "call_model")

# Compile the builder into an executable graph
# You can customize this by adding interrupt points for state updates
graph = builder.compile(
    interrupt_before=[],  # Add node names here to update state before they're called
    interrupt_after=[],  # Add node names here to update state after they're called
)
graph.name = "ReAct Agent"  # This customizes the name in LangSmit



# Run the graph - example usage by running the call_model function
# Run the call_model function using asyncio
if __name__ == "__main__":
    # Initialize the state with the first user message
    initial_state = State(messages=[
        AIMessage(role="user", content="Look at my 5 latest emails and check if there are any job application confirmations. "
                                       "If there are, extract the details like company name, role, and date applied. "
                                       "Then, fill in those details in the Google Sheet I created — specifically in the cells "
                                       "under the respective columns: Company name, Role, and Date applied.")
    ])
    
    # Run the call_model function with the initialized state
    asyncio.run(call_model(initial_state, RunnableConfig()))


