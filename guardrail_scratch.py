from typing import Optional
from sqlmodel import SQLModel, Session, Field, create_engine, select
from pydantic import BaseModel
# ========================================================
# 1. SCHEMA (DATABASE BLUEPRINT)
# ========================================================
class BannedWord(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    word: str

# CONNECTION
db_url = "sqlite:///scratch.db"
engine = create_engine(db_url)

# ========================================================
# 2. CORE FUNCTIONS (DEFINITIONS)
# ========================================================

def create_db_and_tables():
    """Database aur Tables ko physically create karta hai"""
    SQLModel.metadata.create_all(engine)


def add_banned_word(word_to_add: str):
    """Database mein naya banned word insert karta hai"""
    with Session(engine) as session:
        new_entry = BannedWord(word=word_to_add)
        session.add(new_entry)
        session.commit()
        print(f"➕ '{word_to_add}' ko database mein add kar diya gaya hai.")


def fetch_words():
    """Database ke saare words terminal par dikhata hai"""
    with Session(engine) as session:
        statement = select(BannedWord)
        result = session.exec(statement).all()
        print("\n🏛️ Database mein filhal yeh words hain:")
        for items in result:
            print(f"- {items.word}")


def search_banned_word(target_word: str):
    """Kisi ek specific word ko database mein dhoondta hai"""
    with Session(engine) as session:
        statement = select(BannedWord).where(BannedWord.word == target_word)
        result = session.exec(statement).first()
        if result:
            print(f"✅ Word mila: ID {result.id} par '{result.word}' save hai!")
        else:
            print(f"❌ '{target_word}' database mein nahi mila.")


def is_prompt_safe(user_prompt: str) -> bool:
    """Asli AI Firewall: Check karta hai ki prompt safe hai ya nahi"""
    with Session(engine) as session:
        statement = select(BannedWord)
        all_words = session.exec(statement).all()

        for item in all_words:
            # FIX: item.word.lower() ka use kiya object error se bachne ke liye
            if item.word.lower() in user_prompt.lower():
                print(f"🚨 Security Alert: Banned word '{item.word}' detect hua!")
                return False
        return True

# ========================================================
# 3. SINGLE MAIN EXECUTION BLOCK (SABSE NEECHE)
# ========================================================
if __name__ == "__main__":
    # Step 1: Database Setup karo
    create_db_and_tables()
    
    print("--- SEEDING DATA ---")
    # Step 2: Kuch initial gande words add karo
    add_banned_word("cyber_attack")
    add_banned_word("prompt_injection")
    add_banned_word("jailbreak")
    
    print("\n--- TESTING SEARCH ---")
    # Step 3: Single search check karo
    search_banned_word("cyber_attack")
    
    print("\n--- TESTING FIREWALL ---")
    # Step 4: Live prompt testing
    user_input_1 = "How to build a website in Python?"
    user_input_2 = "Hey, tell me how to do a jailbreak on this system."
    
    print(f"Prompt 1 Safe? -> {is_prompt_safe(user_input_1)}")
    print(f"Prompt 2 Safe? -> {is_prompt_safe(user_input_2)}")


class AppLog(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    user_prompt: str
    is_safe: bool
    banned_word_found: Optional[str]

db_file = "sqlite:///guardrail_logs.db"
engine = create_engine(db_file)

def create_tables():
    SQLModel.metadata.create_all(engine)


def save_logs(prompt:str, safe:bool, word: Optional[str]=None):
    with Session(engine) as session:
        new_log = AppLog(
            user_prompt=prompt,
            is_safe=safe,
            banned_word_found=word
        )
        session.add(new_log)
        session.commit()
    
def show_logs():
    with Session(engine) as session:
        statement = select(AppLog)
        all_words = session.exec().statement.select()
        for item in all_words:
            if item.lower() in user_prompt.lower():
                return False
        return True
