from sqlalchemy import Column, Integer, String, Boolean, ForeignKey, DateTime
from sqlalchemy.orm import relationship
from app.database import Base
import datetime

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)

    # tasks = relationship("Task", back_populates="owner")

class Task(Base):
    __tablename__ = "tasks"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, index=True)
    description = Column(String)
    priority = Column(Integer, default=1)  # 1 (Low), 2 (Medium), 3 (High)
    deadline = Column(DateTime, nullable=True)
    is_completed = Column(Boolean, default=False)
    owner_id = Column(Integer, ForeignKey("users.id"))

    # owner = relationship("User", back_populates="tasks")