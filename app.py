import streamlit as st
import sqlite3
from datetime import datetime
import pandas as pd
import hashlib
import hmac
import secrets
import base64

DB_NAME = "daily_record_db.sqlite3"

# ========== 密码加密与验证 ==========
def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    hash_bytes = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100_000)
    return base64.b64encode(salt + hash_bytes).decode()

def verify_password(password: str, stored_hash_b64: str) -> bool:
    stored_bytes = base64.b64decode(stored_hash_b64)
    salt = stored_bytes[:16]
    stored_hash = stored_bytes[16:]
    new_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100_000)
    return hmac.compare_digest(new_hash, stored_hash)

# ========== 数据库操作 ==========
def init_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password_hash TEXT
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS weight_log (
            username TEXT,
            date TEXT,
            time TEXT,
            weight REAL,
            FOREIGN KEY (username) REFERENCES users (username)
        )
    ''')
    conn.commit()
    conn.close()

def create_user(username, password):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    password_hash = hash_password(password)
    try:
        c.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, password_hash))
        conn.commit()
    except sqlite3.IntegrityError:
        pass  # 用户已存在
    conn.close()

def verify_user(username, password):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
    result = c.fetchone()
    conn.close()
    if result:
        stored_hash = result[0]
        return verify_password(password, stored_hash)
    return False

def log_weight(username, date_of_measure,time_of_measure, weight):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("INSERT INTO weight_log (username, date, time, weight) VALUES (?, ?, ?, ?)",
              (username, date_of_measure, time_of_measure, weight))
    conn.commit()
    conn.close()

def get_user_weights(username):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("SELECT date, time, weight FROM weight_log WHERE username = ? ORDER BY date, time", (username,))
    rows = c.fetchall()
    conn.close()
    return rows

# ========== 主程序 ==========
def main():
    st.set_page_config(page_title="每日记录系统", page_icon="⚖️")
    init_db()

    if "logged_in" not in st.session_state:
        st.session_state.logged_in = False
        st.session_state.username = ""

    if not st.session_state.logged_in:
        st.title("用户登录")
        username = st.text_input("用户名")
        password = st.text_input("密码", type="password")

        if st.button("登录"):
            if verify_user(username, password):
                st.success("登录成功")
                st.session_state.logged_in = True
                st.session_state.username = username
                st.rerun()
            else:
                st.error("用户名或密码错误")

        st.markdown("---")
        st.subheader("注册新用户（仅限首次使用）")
        new_user = st.text_input("新用户名")
        new_pass = st.text_input("新密码", type="password")
        if st.button("注册"):
            if new_user and new_pass:
                create_user(new_user, new_pass)
                st.success("用户注册成功，请返回上方登录")
            else:
                st.warning("请输入用户名和密码")

    else: # st.session_state.logged_in exist and is True
        st.title(f"欢迎，{st.session_state.username}")
        tab1,tab2 = st.tabs(['记录体重','查看历史体重'])
        with tab1:
            st.subheader("记录体重")
            date_of_measure = st.date_input("测量日期")
            time_of_measure = st.time_input("测量时间")
            weight = st.number_input("体重(kg)", min_value=0.0, format="%.1f")
            # print(type(date_of_measure))
            # print(date_of_measure.isoformat())
            # print(type(time_of_measure))
            # print(time_of_measure.isoformat())
            # print(type(weight))
            # print(weight)

            if st.button("提交记录"):
                log_weight(st.session_state.username, date_of_measure.isoformat(), time_of_measure.isoformat(), weight)
                st.success("记录已保存")
        
        with tab2:
            st.subheader("体重趋势图")
            data = get_user_weights(st.session_state.username)
            if data:
                df = pd.DataFrame(data, columns=["日期","时间", "体重"])
                df["日期"] = pd.to_datetime(df["日期"])
                # df["时间"] = pd.to_datetime(df["时间"])
                df = df.sort_values("日期")
                df.set_index("日期", inplace=True)
                st.line_chart(df["体重"])
            else:
                st.info("暂无体重记录，请先在“记录体重”页添加数据。")

        if st.button("退出登录"):
            st.session_state.logged_in = False
            st.session_state.username = ""
            st.rerun()

if __name__ == "__main__":
    main()
