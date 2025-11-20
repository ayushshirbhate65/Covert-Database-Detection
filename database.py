import sqlite3
from faker import Faker
import random

# Initialize Faker
fake = Faker()

# Function to create a database with random tables and data
def create_random_database(db_name):
    # Connect to SQLite database (it will be created if it doesn't exist)
    conn = sqlite3.connect(f'{db_name}.db')
    cursor = conn.cursor()

    # Random number of tables (1 to 5)
    num_tables = random.randint(1, 5)
    
    for i in range(num_tables):
        table_name = f'table_{i+1}'
        # Random number of columns (2 to 5)
        num_columns = random.randint(2, 5)
        
        # Generate column names and types
        columns = []
        for j in range(num_columns):
            col_name = f'column_{j+1}'
            col_type = random.choice(['TEXT', 'INTEGER', 'REAL'])
            columns.append(f'{col_name} {col_type}')
        
        # Create table
        create_table_query = f'CREATE TABLE {table_name} (id INTEGER PRIMARY KEY, {", ".join(columns)})'
        cursor.execute(create_table_query)
        
        # Insert random data into the table
        num_rows = random.randint(5, 10)  # Random number of rows (5 to 10)
        for _ in range(num_rows):
            values = []
            for j in range(num_columns):
                if columns[j].endswith('TEXT'):
                    values.append(f"'{fake.word()}'")
                elif columns[j].endswith('INTEGER'):
                    values.append(str(random.randint(1, 100)))
                elif columns[j].endswith('REAL'):
                    values.append(str(round(random.uniform(1.0, 100.0), 2)))
            
            insert_query = f'INSERT INTO {table_name} ({", ".join([col.split()[0] for col in columns])}) VALUES ({", ".join(values)})'
            cursor.execute(insert_query)
    
    # Commit and close the connection
    conn.commit()
    conn.close()

# Create between 1 to 5 random databases
num_databases = random.randint(1, 5)
for db_num in range(num_databases):
    db_name = f'database_{db_num+1}'
    create_random_database(db_name)
    print(f'Created database: {db_name}.db')

print("All databases created successfully!")