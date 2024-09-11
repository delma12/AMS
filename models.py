from sqlalchemy import Column, Integer, String, Boolean, Float, ForeignKey, Date
from database import Base
from sqlalchemy.orm import relationship

class User(Base):
    __tablename__ = 'users'
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    is_admin = Column(Boolean, default=False)
    apprentices = relationship("Apprentice", back_populates="creator")


class Apprentice(Base):
    __tablename__ = 'apprentices'

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True)
    email = Column(String)
    age = Column(Integer)
    cohort_year = Column(Integer)
    job_role = Column(String)
    skills = Column(String)
    creator_id = Column(Integer, ForeignKey('users.id'))
    creator = relationship("User", back_populates="apprentices")


