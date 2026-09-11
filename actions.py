from nemoguardrails.actions import action

# Memory database list
memory_db = []

@action(name="log_to_memory")
async def log_to_memory(activity_val: str = None):
    if activity_val:
        memory_db.append(activity_val)
        print(f"\n📊 [MEMORY DB STATUS]: {memory_db}\n")
        return True
    return False