import os
import sqlite3
from typing import Any, List, Sequence

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_DB_PATH = os.path.join(
    BASE_DIR, "cornell-course-sphere-data", "roster_reviews.sqlite.db"
)


def create_connection():
    db_path = os.getenv("SQLITE_DB_PATH", DEFAULT_DB_PATH)
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = sqlite3.connect(db_path)
    return conn


def init_db():
    conn = create_connection()
    cursor = conn.cursor()
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS courses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            code TEXT NOT NULL,
            title TEXT NOT NULL,
            section_id INTEGER,
            semester TEXT,
            department TEXT,
            instructor TEXT
        )
        """
    )
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS course_descriptions (
            id INTEGER PRIMARY KEY,
            description TEXT NOT NULL
        )
        """
    )
    cursor.execute("SELECT COUNT(*) FROM courses")
    if cursor.fetchone()[0] == 0:
        cursor.executemany(
            """
            INSERT INTO courses (id, code, title, section_id, semester, department, instructor)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (1, "CS 2110", "Object-Oriented Programming and Data Structures", 101, "Fall 2024", "CS", "Myers"),
                (2, "CS 4820", "Introduction to Analysis of Algorithms", 102, "Spring 2025", "CS", "Kleinberg"),
                (3, "MATH 1920", "Multivariable Calculus for Engineers", 201, "Fall 2024", "MATH", "Strogatz"),
            ],
        )
        cursor.executemany(
            "INSERT INTO course_descriptions (id, description) VALUES (?, ?)",
            [
                (1, "Intermediate programming in a high-level language and introduction to computer science."),
                (2, "Develops techniques used in the design and analysis of algorithms."),
                (3, "Partial derivatives, multiple integrals, and vector calculus."),
            ],
        )
    conn.commit()
    conn.close()


def execute_query(query: str, params: Sequence[Any] = ()) -> List[Any]:
    conn = create_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(query, tuple(params))
        rows = cursor.fetchall()
        conn.commit()
        return rows
    finally:
        conn.close()


init_db()

if __name__ == "__main__":
    print(execute_query("SELECT * FROM courses"))
