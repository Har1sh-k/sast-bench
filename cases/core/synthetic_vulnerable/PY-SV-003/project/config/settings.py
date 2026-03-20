"""Task assistant agent configuration."""

TASK_TIMEOUT = 30
MAX_TASKS_PER_MESSAGE = 10
WORKSPACE_DIR = "/workspace"

# Command templates for supported task types.
# NOTE: These templates exist for documentation; the executor uses them
# via string formatting without sanitising the interpolated values.
COMMAND_TEMPLATES = {
    "log": 'echo "Task: {description}" >> /var/log/agent/tasks.log',
    "notify": 'notify-send "Agent" "{description}"',
    "record": 'echo "{description}" | tee -a /workspace/tasks.txt',
}
