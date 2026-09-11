
from typing import Optional
from sqlmodel import SQLModel, Field, create_engine, Session, select

class BannedWord(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    word : str

db_url = "sqlite:///ai_guardrail.db"
engine = create_engine(db_url)

def create_db_and_tables():
    SQLModel.metadata.create_all(engine)
    print("Database aur BannedWord table kamyabi se ban gayi hai! 🎉")
create_db_and_tables()

def insert_banned_word():
    with Session(engine) as session:
        new_entry = BannedWord(word="prompt_injection")
        session.add(new_entry)
        session.commit()
        print("2. Pehla banned word ('prompt_injection') database mein save ho gaya! 🔥")
        
if __name__ == "__main__":
    create_db_and_tables()  # Pehle table banegi
    insert_banned_word()  
    
def fetch_banned_words():
    with Session(engine) as session:
        statement = select(BannedWord)
        words = session.exec(statement).all()
        print("Database mein yeh banned words hain:")

        for items in words:
            print(f"- {items.word}")

fetch_banned_words()