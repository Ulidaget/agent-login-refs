import streamlit as st
import tools
import json
import os
from datetime import datetime
import boto3
import hmac
import base64
import hashlib
import pandas as pd
from botocore.exceptions import ClientError
import logging

# Configurar logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configuración de AWS Cognito
USER_POOL_ID = 'us-east-1_DzVB7yQ87'
CLIENT_ID = 'm47hdqpevjk6hv6m7ul9jqonv'
CLIENT_SECRET = '18i75h8ho88rrkq2gnkg1f6amdm09ilt6g137iot4b897ttqa8ps'
REGION_NAME = 'us-east-1'

# Funciones auxiliares

# new add
def list_all_conversations():
    conversations = {}
    root_folder = "conversations"
    for user_folder in os.listdir(root_folder):
        user_path = os.path.join(root_folder, user_folder)
        if os.path.isdir(user_path):
            user_conversations = [f for f in os.listdir(user_path) if f.endswith('.json')]
            conversations[user_folder] = user_conversations
    return conversations

def list_users():
    client = boto3.client('cognito-idp', region_name=REGION_NAME)
    response = client.list_users(UserPoolId=USER_POOL_ID)
    return response['Users']

def create_user(email, temporary_password, nickname):
    client = boto3.client('cognito-idp', region_name=REGION_NAME)
    try:
        response = client.admin_create_user(
            UserPoolId=USER_POOL_ID,
            Username=email,
            UserAttributes=[
                {'Name': 'email', 'Value': email},
                {'Name': 'email_verified', 'Value': 'true'},
                {'Name': 'nickname', 'Value': nickname},
                {'Name': 'custom:is_admin', 'Value': 'true' if is_admin else 'false'}
            ],
            TemporaryPassword=temporary_password,
            MessageAction='SUPPRESS'
        )
        return True, "User created successfully"
    except Exception as e:
        return False, str(e)

def update_user(username, attributes):
    client = boto3.client('cognito-idp', region_name=REGION_NAME)
    try:
        response = client.admin_update_user_attributes(
            UserPoolId=USER_POOL_ID,
            Username=username,
            UserAttributes=attributes
        )
        return True, "User updated successfully"
    except Exception as e:
        return False, str(e)

def delete_user(username):
    client = boto3.client('cognito-idp', region_name=REGION_NAME)
    try:
        response = client.admin_delete_user(
            UserPoolId=USER_POOL_ID,
            Username=username
        )
        return True, "User deleted successfully"
    except Exception as e:
        return False, str(e)
    
def save_conversation(messages, filename):
    with open(filename, 'w') as f:
        json.dump(messages, f)

def load_conversation(filename):
    if os.path.exists(filename):
        with open(filename, 'r') as f:
            return json.load(f)
    return []

def generate_new_filename():
    return f"conversation_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

def start_new_conversation():
    st.session_state.messages = []
    st.session_state.current_conversation = "New conversation"
    st.session_state.conversation_filename = generate_new_filename()

def get_secret_hash(username):
    msg = username + CLIENT_ID
    dig = hmac.new(str(CLIENT_SECRET).encode('utf-8'), 
        msg=str(msg).encode('utf-8'), digestmod=hashlib.sha256).digest()
    d2 = base64.b64encode(dig).decode()
    return d2

def login_old(email, password):
    client = boto3.client('cognito-idp', region_name=REGION_NAME)
    secret_hash = get_secret_hash(email)
    try:
        response = client.initiate_auth(
            ClientId=CLIENT_ID,
            AuthFlow='USER_PASSWORD_AUTH',
            AuthParameters={
                'USERNAME': email,
                'PASSWORD': password,
                'SECRET_HASH': secret_hash
            }
        )

        if 'ChallengeName' in response and response['ChallengeName'] == 'NEW_PASSWORD_REQUIRED':
            st.session_state.session = response['Session']
            st.session_state.awaiting_new_password = True
            st.session_state.email = email
            st.session_state.user_attributes = json.loads(response['ChallengeParameters']['userAttributes'])
            st.rerun()   # Redirigir automáticamente a la pantalla de cambio de contraseña
        
        st.session_state.authenticated = True
        st.session_state.token = response['AuthenticationResult']['IdToken']
        st.session_state.awaiting_new_password = False
        return True, "Login successful"
    
    except client.exceptions.NotAuthorizedException:
        return False, "Invalid email or password"
    except client.exceptions.UserNotFoundException:
        return False, "User not found"
    except client.exceptions.UserNotConfirmedException:
        return False, "User is not confirmed"
    except client.exceptions.PasswordResetRequiredException:
        return False, "Password reset required"
    except Exception as e:
        return False, f"An unexpected error occurred: {str(e)}"

def complete_new_password_challenge(email, new_password, session, nickname):
    client = boto3.client('cognito-idp', region_name=REGION_NAME)
    secret_hash = get_secret_hash(email)
    try:
        response = client.respond_to_auth_challenge(
            ClientId=CLIENT_ID,
            ChallengeName='NEW_PASSWORD_REQUIRED',
            Session=session,
            ChallengeResponses={
                'USERNAME': email,
                'NEW_PASSWORD': new_password,
                'SECRET_HASH': secret_hash,
                'userAttributes.nickname': nickname,
            }
        )
        st.session_state.authenticated = True
        st.session_state.token = response['AuthenticationResult']['IdToken']
        st.session_state.awaiting_new_password = False
        return True, "Password updated and logged in successfully!"
    except Exception as e:
        return False, f"An error occurred: {str(e)}"

def init_session_state():
    if 'authenticated' not in st.session_state:
        st.session_state.authenticated = False
    if 'awaiting_new_password' not in st.session_state:
        st.session_state.awaiting_new_password = False
    if 'email' not in st.session_state:
        st.session_state.email = None

def login_page():

    st.markdown("<h1 style='text-align: center;'> BIENVENIDO</h1>", unsafe_allow_html=True)
    
    st.markdown("""
    <style>
        .stTextInput > div > div > input {
            width: 100%;
        }
        .stButton > button {
            width: 100%;
        }
    </style>
    """, unsafe_allow_html=True)

    col1, col2, col3 = st.columns([1,2,1])

    with col2:
        email = st.text_input("**Email :**", placeholder="ejemplo@dominio.com", key="email_input")
        # email = st.text_input(label="<strong>Email :</strong>",placeholder="ejemplo@dominio.com")
        password = st.text_input("**Password :**",placeholder="********", type="password")
    
        if st.button("Login"):
            success, message = login(email, password)
            if success:
                st.success(message)
                st.session_state.authenticated = True
                st.session_state.email = email
                st.rerun() 
            else:
                st.error(message)
   
def new_password_page():
    st.title("Set New Password")
    new_password = st.text_input("New Password", type="password")
    confirm_password = st.text_input("Confirm Password", type="password")
    nickname = st.text_input("Nickname")

    if st.button("Submit"):
        if new_password != confirm_password:
            st.error("Passwords do not match")
        else:
            success, message = complete_new_password_challenge(st.session_state.email, new_password, st.session_state.session, nickname)
            if success:
                st.success(message)
                st.session_state.authenticated = True
                st.rerun()
            else:
                st.error(message)

def chatbot_page_old():
    st.markdown("<h1 style='text-align: center;'> 🤖 Honne IA 3.0 Pinecone</h1>", unsafe_allow_html=True)

    user_folder = f"conversations/{st.session_state.email.split('@')[0]}"
    if not os.path.exists(user_folder):
        os.makedirs(user_folder)

    saved_conversations = [f for f in os.listdir(user_folder) if f.endswith('.json')]
    
    if st.sidebar.button("Start New Conversation"):
        start_new_conversation()

    selected_conversation = st.sidebar.selectbox(
        "Load or start a conversation",
        ["New conversation"] + saved_conversations,
        key="conversation_selector"
    )

    if selected_conversation == "New conversation":
        if "messages" not in st.session_state or st.session_state.current_conversation != "New conversation":
            start_new_conversation()
    else:
        if "current_conversation" not in st.session_state or st.session_state.current_conversation != selected_conversation:
            st.session_state.messages = load_conversation(os.path.join(user_folder, selected_conversation))
            st.session_state.current_conversation = selected_conversation
            st.session_state.conversation_filename = selected_conversation

    if "messages" in st.session_state:
        for message in st.session_state.messages:
            with st.chat_message(message["role"]):
                st.write(message["content"])

    user_input = st.chat_input("Type your message here")

    if user_input:
        st.session_state.messages.append({"role": "user", "content": user_input})
        
        llm_response = tools.answer_query(user_input)
        formatted_answer = tools.format_answer(llm_response)
        
        st.session_state.messages.append({"role": "assistant", "content": formatted_answer})

        save_conversation(st.session_state.messages, os.path.join(user_folder, st.session_state.conversation_filename))
        
        # Aquí forzamos la actualización de la interfaz
        st.rerun()  # Cambiado de st.experimental_rerun()

    if st.sidebar.button("Logout"):
        st.session_state.authenticated = False
        st.session_state.email = None
        st.session_state.token = None
        st.session_state.awaiting_new_password = False
        st.session_state.clear()
        st.rerun()  # Cambiado de st.experimental_rerun()

def process_llm_response(user_input, show_references):
    
    if show_references:
        llm_response = tools.answer_query(user_input)
        formatted_answer = tools.format_answer(llm_response)
        return formatted_answer
    else:
        llm_response = tools.answer_query_old(user_input)
        # Asumiendo que llm_response es un diccionario con claves 'answer' y 'references'
        
        return llm_response

def chatbot_page_old():
    st.markdown("<h1 style='text-align: center;'> 🤖 Honne IA 3.0 Pinecone</h1>", unsafe_allow_html=True)

    user_folder = f"conversations/{st.session_state.email.split('@')[0]}"
    if not os.path.exists(user_folder):
        os.makedirs(user_folder)

    saved_conversations = [f for f in os.listdir(user_folder) if f.endswith('.json')]
    
    if st.sidebar.button("Start New Conversation"):
        start_new_conversation()

    selected_conversation = st.sidebar.selectbox(
        "Load or start a conversation",
        ["New conversation"] + saved_conversations,
        key="conversation_selector"
    )

    # Agregar el toggle para mostrar referencias
    show_references = st.sidebar.checkbox("Show References", value=True)

    if selected_conversation == "New conversation":
        if "messages" not in st.session_state or st.session_state.current_conversation != "New conversation":
            start_new_conversation()
    else:
        if "current_conversation" not in st.session_state or st.session_state.current_conversation != selected_conversation:
            st.session_state.messages = load_conversation(os.path.join(user_folder, selected_conversation))
            st.session_state.current_conversation = selected_conversation
            st.session_state.conversation_filename = selected_conversation

    if "messages" in st.session_state:
        for message in st.session_state.messages:
            with st.chat_message(message["role"]):
                st.write(message["content"])

    user_input = st.chat_input("Type your message here")

    if user_input:
        st.session_state.messages.append({"role": "user", "content": user_input})
        
        assistant_response = process_llm_response(user_input, show_references)
        st.session_state.messages.append({"role": "assistant", "content": assistant_response})

        save_conversation(st.session_state.messages, os.path.join(user_folder, st.session_state.conversation_filename))
        
        st.rerun()

    if st.sidebar.button("Logout"):
        st.session_state.authenticated = False
        st.session_state.email = None
        st.session_state.token = None
        st.session_state.awaiting_new_password = False
        st.session_state.clear()
        st.rerun()

def login_old_2(email, password):
    client = boto3.client('cognito-idp', region_name=REGION_NAME)
    secret_hash = get_secret_hash(email)
    try:
        response = client.initiate_auth(
            ClientId=CLIENT_ID,
            AuthFlow='USER_PASSWORD_AUTH',
            AuthParameters={
                'USERNAME': email,
                'PASSWORD': password,
                'SECRET_HASH': secret_hash
            }
        )

        if 'ChallengeName' in response and response['ChallengeName'] == 'NEW_PASSWORD_REQUIRED':
            st.session_state.session = response['Session']
            st.session_state.awaiting_new_password = True
            st.session_state.email = email
            st.session_state.user_attributes = json.loads(response['ChallengeParameters']['userAttributes'])
            st.rerun()
        
        st.session_state.authenticated = True
        st.session_state.token = response['AuthenticationResult']['IdToken']
        st.session_state.awaiting_new_password = False
        
        # Obtener el nombre del usuario
        user_info = client.get_user(AccessToken=response['AuthenticationResult']['AccessToken'])
        st.session_state.user_name = "Usuario"  # Valor por defecto
        for attribute in user_info['UserAttributes']:
            if attribute['Name'] == 'name':
                st.session_state.user_name = attribute['Value']
                break
            elif attribute['Name'] == 'email':
                # Si no hay nombre, usamos el email como alternativa
                st.session_state.user_name = attribute['Value'].split('@')[0]
        
        # print(f"Nombre de usuario guardado: {st.session_state.user_name}")  # Para depuración
        
        return True, "Login successful"
    
    except Exception as e:
        print(f"Error durante el inicio de sesión: {str(e)}")  # Para depuración
        return False, f"An unexpected error occurred: {str(e)}"

def logout():
    st.session_state.authenticated = False
    st.session_state.email = None
    st.session_state.token = None
    st.session_state.user_name = None  # Limpiar el nombre de usuario al cerrar sesión
    st.session_state.awaiting_new_password = False
    st.session_state.clear()
    st.rerun()
        
def chatbot_page_old():
    # Obtener el nombre del usuario de la sesión
    user_name = st.session_state.get('user_name', 'Usuario')
    
    st.markdown("""
    <style>
        .stButton > button {
            width: 100%;
        }
    </style>
    """, unsafe_allow_html=True)
    
    # Mostrar el saludo personalizado
    st.markdown(f"<h1 style='text-align: center;'>¡Bienvenido, {user_name}! 👋</h1>", unsafe_allow_html=True)
    st.markdown("<h2 style='text-align: center;'>🤖 Honne IA 3.0 Pinecone</h2>", unsafe_allow_html=True)

    user_folder = f"conversations/{st.session_state.email.split('@')[0]}"
    if not os.path.exists(user_folder):
        os.makedirs(user_folder)

    saved_conversations = [f for f in os.listdir(user_folder) if f.endswith('.json')]
    
    if st.sidebar.button("Start New Conversation"):
        start_new_conversation()

    selected_conversation = st.sidebar.selectbox(
        "Load or start a conversation",
        ["New conversation"] + saved_conversations,
        key="conversation_selector"
    )
    
    # checkbox
    show_references = st.sidebar.checkbox("Show References", value=True, key="show_references")


    if selected_conversation == "New conversation":
        if "messages" not in st.session_state or st.session_state.current_conversation != "New conversation":
            start_new_conversation()
    else:
        if "current_conversation" not in st.session_state or st.session_state.current_conversation != selected_conversation:
            st.session_state.messages = load_conversation(os.path.join(user_folder, selected_conversation))
            st.session_state.current_conversation = selected_conversation
            st.session_state.conversation_filename = selected_conversation

    if "messages" in st.session_state:
        for message in st.session_state.messages:
            with st.chat_message(message["role"]):
                st.write(message["content"])

    user_input = st.chat_input("Type your message here")

    if user_input:
        st.session_state.messages.append({"role": "user", "content": user_input})
        
        assistant_response = process_llm_response(user_input, show_references)
        st.session_state.messages.append({"role": "assistant", "content": assistant_response})

        save_conversation(st.session_state.messages, os.path.join(user_folder, st.session_state.conversation_filename))
        
        st.rerun()
        
    if st.sidebar.button("Logout", key="logout-button-2"):
        logout()

# def chatbot_page():
#     # Obtener el nombre del usuario de la sesión
#     user_name = st.session_state.get('user_name', 'Usuario')
    
#     st.markdown("""
#     <style>
#         .stButton > button {
#             width: 100%;
#         }
#     </style>
#     """, unsafe_allow_html=True)
    
#     # Mostrar el saludo personalizado
#     st.markdown(f"<h1 style='text-align: center;'>¡Bienvenido, {user_name}! 👋</h1>", unsafe_allow_html=True)
#     st.markdown("<h2 style='text-align: center;'>🤖 Honne IA 3.0 Pinecone</h2>", unsafe_allow_html=True)

#     # Opción para administradores de ver todas las conversaciones
#     if st.session_state.get('is_admin', False):
#         view_mode = st.radio("View mode", ["My Conversations", "All Conversations"])
#     else:
#         view_mode = "My Conversations"

#     if view_mode == "My Conversations":
#         user_folder = f"conversations/{st.session_state.email.split('@')[0]}"
#         if not os.path.exists(user_folder):
#             os.makedirs(user_folder)
#         saved_conversations = [f for f in os.listdir(user_folder) if f.endswith('.json')]
#     else:
#         conversations = list_all_conversations()
#         saved_conversations = [f"{user}/{conv}" for user, convs in conversations.items() for conv in convs]

#     if st.sidebar.button("Start New Conversation"):
#         start_new_conversation()

#     selected_conversation = st.sidebar.selectbox(
#         "Load or start a conversation",
#         ["New conversation"] + saved_conversations,
#         key="conversation_selector"
#     )
    
#     # checkbox
#     show_references = st.sidebar.checkbox("Show References", value=True, key="show_references")

#     if selected_conversation == "New conversation":
#         if "messages" not in st.session_state or st.session_state.current_conversation != "New conversation":
#             start_new_conversation()
#     else:
#         if "current_conversation" not in st.session_state or st.session_state.current_conversation != selected_conversation:
#             if view_mode == "My Conversations":
#                 st.session_state.messages = load_conversation(os.path.join(user_folder, selected_conversation))
#             else:
#                 user, conv = selected_conversation.split('/', 1)
#                 st.session_state.messages = load_conversation(os.path.join("conversations", user, conv))
#             st.session_state.current_conversation = selected_conversation
#             st.session_state.conversation_filename = selected_conversation.split('/')[-1]

#     if "messages" in st.session_state:
#         for message in st.session_state.messages:
#             with st.chat_message(message["role"]):
#                 st.write(message["content"])

#     user_input = st.chat_input("Type your message here")

#     if user_input:
#         st.session_state.messages.append({"role": "user", "content": user_input})
        
#         assistant_response = process_llm_response(user_input, show_references)
#         st.session_state.messages.append({"role": "assistant", "content": assistant_response})

#         if view_mode == "My Conversations":
#             save_conversation(st.session_state.messages, os.path.join(user_folder, st.session_state.conversation_filename))
#         else:
#             user, conv = selected_conversation.split('/', 1)
#             save_conversation(st.session_state.messages, os.path.join("conversations", user, conv))
        
#         st.rerun()
        
#     if st.sidebar.button("Logout", key="logout-button-2"):
#         logout()

# def chatbot_page():
#     user_name = st.session_state.get('user_name', 'Usuario')
    
#     st.markdown(f"<h1 style='text-align: center;'>¡Bienvenido, {user_name}! 👋</h1>", unsafe_allow_html=True)
#     st.markdown("<h2 style='text-align: center;'>🤖 Honne IA 3.0 Pinecone</h2>", unsafe_allow_html=True)

#     # Inicializar el modo de visualización en el estado de la sesión si no existe
#     if 'view_mode' not in st.session_state:
#         st.session_state.view_mode = "My Conversations"

#     # Opción para administradores de ver todas las conversaciones
#     if st.session_state.get('is_admin', False):
#         new_view_mode = st.radio("View mode", ["My Conversations", "All Conversations"])
#         if new_view_mode != st.session_state.view_mode:
#             st.session_state.view_mode = new_view_mode
#             st.rerun()  # Forzar recarga de la página
#     else:
#         st.session_state.view_mode = "My Conversations"

#     # Cargar las conversaciones basadas en el modo de visualización
#     if st.session_state.view_mode == "My Conversations":
#         user_folder = f"conversations/{st.session_state.email.split('@')[0]}"
#         if not os.path.exists(user_folder):
#             os.makedirs(user_folder)
#         saved_conversations = [f for f in os.listdir(user_folder) if f.endswith('.json')]
#     else:
#         conversations = list_all_conversations()
#         saved_conversations = [f"{user}/{conv}" for user, convs in conversations.items() for conv in convs]

#     if st.sidebar.button("Start New Conversation"):
#         start_new_conversation()

#     selected_conversation = st.sidebar.selectbox(
#         "Load or start a conversation",
#         ["New conversation"] + saved_conversations,
#         key="conversation_selector"
#     )
    
#     show_references = st.sidebar.checkbox("Show References", value=True, key="show_references")

#     if selected_conversation == "New conversation":
#         if "messages" not in st.session_state or st.session_state.current_conversation != "New conversation":
#             start_new_conversation()
#     else:
#         if "current_conversation" not in st.session_state or st.session_state.current_conversation != selected_conversation:
#             if st.session_state.view_mode == "My Conversations":
#                 user_folder = f"conversations/{st.session_state.email.split('@')[0]}"
#                 st.session_state.messages = load_conversation(os.path.join(user_folder, selected_conversation))
#             else:
#                 user, conv = selected_conversation.split('/', 1)
#                 st.session_state.messages = load_conversation(os.path.join("conversations", user, conv))
#             st.session_state.current_conversation = selected_conversation
#             st.session_state.conversation_filename = selected_conversation.split('/')[-1]

#     if "messages" in st.session_state:
#         for message in st.session_state.messages:
#             with st.chat_message(message["role"]):
#                 st.write(message["content"])

#     user_input = st.chat_input("Type your message here")

#     if user_input:
#         st.session_state.messages.append({"role": "user", "content": user_input})
        
#         assistant_response = process_llm_response(user_input, show_references)
#         st.session_state.messages.append({"role": "assistant", "content": assistant_response})

#         if st.session_state.view_mode == "My Conversations":
#             user_folder = f"conversations/{st.session_state.email.split('@')[0]}"
#             save_conversation(st.session_state.messages, os.path.join(user_folder, st.session_state.conversation_filename))
#         else:
#             user, conv = st.session_state.current_conversation.split('/', 1)
#             save_conversation(st.session_state.messages, os.path.join("conversations", user, conv))
        
#         st.rerun()
        
#     if st.sidebar.button("Logout", key="logout-button-2"):
#         logout()


def chatbot_page():
    user_name = st.session_state.get('user_name', 'Usuario')
    
    st.markdown(f"<h1 style='text-align: center;'>¡Bienvenido, {user_name}! 👋</h1>", unsafe_allow_html=True)
    st.markdown("<h2 style='text-align: center;'>🤖 Honne IA 3.0 Pinecone</h2>", unsafe_allow_html=True)

    user_folder = f"conversations/{st.session_state.email.split('@')[0]}"
    if not os.path.exists(user_folder):
        os.makedirs(user_folder)

    saved_conversations = [f for f in os.listdir(user_folder) if f.endswith('.json')]

    if st.sidebar.button("Start New Conversation"):
        start_new_conversation()

    selected_conversation = st.sidebar.selectbox(
        "Load or start a conversation",
        ["New conversation"] + saved_conversations,
        key="conversation_selector"
    )
    
    show_references = st.sidebar.checkbox("Show References", value=True, key="show_references")

    if selected_conversation == "New conversation":
        if "messages" not in st.session_state or st.session_state.current_conversation != "New conversation":
            start_new_conversation()
    else:
        if "current_conversation" not in st.session_state or st.session_state.current_conversation != selected_conversation:
            st.session_state.messages = load_conversation(os.path.join(user_folder, selected_conversation))
            st.session_state.current_conversation = selected_conversation
            st.session_state.conversation_filename = selected_conversation

    if "messages" in st.session_state:
        for message in st.session_state.messages:
            with st.chat_message(message["role"]):
                st.write(message["content"])

    user_input = st.chat_input("Type your message here")

    if user_input:
        st.session_state.messages.append({"role": "user", "content": user_input})
        
        assistant_response = process_llm_response(user_input, show_references)
        st.session_state.messages.append({"role": "assistant", "content": assistant_response})

        save_conversation(st.session_state.messages, os.path.join(user_folder, st.session_state.conversation_filename))
        
        st.rerun()
        
    if st.sidebar.button("Logout", key="logout-button-2"):
        logout()
        
def main_old():
    init_session_state()

    if not st.session_state.authenticated:
        if st.session_state.awaiting_new_password:
            new_password_page()
        else:
            login_page()
    else:
        chatbot_page()
    
    # Mostrar el estado de la sesión para depuración
    # show_session_state()

# New admin page function
def admin_page_old():
    st.title("Admin Dashboard")

    # List Users
    st.header("User List")
    users = list_users()
    for user in users:
        is_admin = any(attr['Name'] == 'custom:is_admin' and attr['Value'].lower() in ['true', '1'] for attr in user['Attributes'])
        st.write(f"Username: {user['Username']}, Status: {user['UserStatus']}, Admin: {is_admin}")
        # st.write(f"Username: {user['Username']}, Status: {user['UserStatus']}")

    # Create User
    st.header("Create New User")
    new_email = st.text_input("Email")
    new_password = st.text_input("Temporary Password", type="password")
    new_nickname = st.text_input("Nickname")
    if st.button("Create User"):
        success, message = create_user(new_email, new_password, new_nickname)
        if success:
            st.success(message)
        else:
            st.error(message)

    # Update User
    st.header("Update User")
    update_username = st.text_input("Username to update")
    update_nickname = st.text_input("New Nickname")
    if st.button("Update User"):
        success, message = update_user(update_username, [{'Name': 'nickname', 'Value': update_nickname}])
        if success:
            st.success(message)
        else:
            st.error(message)

    # Delete User
    st.header("Delete User")
    delete_username = st.text_input("Username to delete")
    if st.button("Delete User"):
        success, message = delete_user(delete_username)
        if success:
            st.success(message)
        else:
            st.error(message)

def admin_page_old2():
    st.title("Admin Dashboard")

    # Select box for choosing admin function
    admin_function = st.selectbox(
        "Choose Admin Function",
        ["Show Users", "Create User", "Update User", "Delete User"]
    )

    if admin_function == "Show Users":
        show_users()
    elif admin_function == "Create User":
        create_user_form()
    elif admin_function == "Update User":
        update_user_form()
    elif admin_function == "Delete User":
        delete_user_form()

def list_users():
    client = boto3.client('cognito-idp', region_name=REGION_NAME)
    response = client.list_users(UserPoolId=USER_POOL_ID)
    return response['Users']

def delete_user(username_or_email):
    client = boto3.client('cognito-idp', region_name=REGION_NAME)
    try:
        # Primero, intentamos encontrar al usuario por correo electrónico
        response = client.list_users(
            UserPoolId=USER_POOL_ID,
            Filter=f'email = "{username_or_email}"'
        )
        
        if response['Users']:
            username = response['Users'][0]['Username']
        else:
            # Si no se encuentra por correo, asumimos que es un nombre de usuario
            username = username_or_email
        
        response = client.admin_delete_user(
            UserPoolId=USER_POOL_ID,
            Username=username
        )
        return True, f"User {username_or_email} deleted successfully"
    except Exception as e:
        return False, str(e)

def admin_page_old():
    st.title("Admin Dashboard")

    # Selector para las diferentes funciones
    admin_function = st.selectbox(
        "Select Function",
        ["Show Users", "Create User", "Update User", "Delete User"]
    )

    if admin_function == "Show Users":
        st.header("User List")
        users = list_users()
        for user in users:
            username = user['Username']
            email = next((attr['Value'] for attr in user['Attributes'] if attr['Name'] == 'email'), 'N/A')
            nickname = next((attr['Value'] for attr in user['Attributes'] if attr['Name'] == 'nickname'), 'N/A')
            is_admin = any(attr['Name'] == 'custom:is_admin' and attr['Value'].lower() in ['true', '1'] for attr in user['Attributes'])
            
            st.write(f"Username: {username}")
            st.write(f"Email: {email}")
            st.write(f"Nickname: {nickname}")
            st.write(f"Status: {user['UserStatus']}")
            st.write(f"Admin: {is_admin}")
            st.write("---")

    elif admin_function == "Create User":
        st.header("Create New User")
        new_email = st.text_input("Email")
        new_password = st.text_input("Temporary Password", type="password")
        new_nickname = st.text_input("Nickname")
        is_admin = st.checkbox("Is Admin")
        if st.button("Create User"):
            success, message = create_user(new_email, new_password, new_nickname, is_admin)
            if success:
                st.success(message)
            else:
                st.error(message)

    elif admin_function == "Update User":
        st.header("Update User")
        update_username = st.text_input("Username to update")
        update_nickname = st.text_input("New Nickname")
        if st.button("Update User"):
            success, message = update_user(update_username, [{'Name': 'nickname', 'Value': update_nickname}])
            if success:
                st.success(message)
            else:
                st.error(message)

    elif admin_function == "Delete User":
        st.header("Delete User")
        delete_identifier = st.text_input("Username or Email to delete")
        if st.button("Delete User"):
            success, message = delete_user(delete_identifier)
            if success:
                st.success(message)
            else:
                st.error(message)

# def admin_page():
#     st.title("Admin Dashboard")

#     # Select box for choosing admin function
#     admin_function = st.selectbox(
#         "Choose Admin Function",
#         ["Show Users", "Create User", "Update User", "Delete User"]
#     )

#     if admin_function == "Show Users":
#         show_users()
#     elif admin_function == "Create User":
#         create_user_form()
#     elif admin_function == "Update User":
#         update_user_form()
#     elif admin_function == "Delete User":
#         delete_user_form()
 
# def admin_page():
#     st.title("Admin Dashboard")

#     admin_function = st.selectbox(
#         "Choose Admin Function",
#         ["Show Users", "Create User", "Update User", "Delete User", "View All Conversations"]
#     )

#     if admin_function == "Show Users":
#         show_users()
#     elif admin_function == "Create User":
#         create_user_form()
#     elif admin_function == "Update User":
#         update_user_form()
#     elif admin_function == "Delete User":
#         delete_user_form()
#     elif admin_function == "View All Conversations":
#         view_all_conversations()

# def view_all_conversations():
#     st.header("All User Conversations")
#     conversations = list_all_conversations()
#     for user, user_conversations in conversations.items():
#         st.subheader(f"User: {user}")
#         for conversation in user_conversations:
#             if st.button(f"View: {conversation}", key=f"{user}_{conversation}"):
#                 view_conversation(user, conversation)

# def view_conversation(user, conversation):
#     filepath = os.path.join("conversations", user, conversation)
#     with open(filepath, 'r') as f:
#         messages = json.load(f)
#     st.subheader(f"Conversation: {conversation}")
#     for message in messages:
#         with st.chat_message(message["role"]):
#             st.write(message["content"])        


# def admin_page():
#     st.title("Admin Dashboard")

#     admin_function = st.selectbox(
#         "Choose Admin Function",
#         ["Show Users", "Create User", "Update User", "Delete User", "View All Conversations"]
#     )

#     if admin_function == "Show Users":
#         show_users()
#     elif admin_function == "Create User":
#         create_user_form()
#     elif admin_function == "Update User":
#         update_user_form()
#     elif admin_function == "Delete User":
#         delete_user_form()
#     elif admin_function == "View All Conversations":
#         view_all_conversations()

# def view_all_conversations():
#     st.header("All User Conversations")
#     conversations = list_all_conversations()
#     for user, user_conversations in conversations.items():
#         st.subheader(f"User: {user}")
#         for conversation in user_conversations:
#             if st.button(f"View: {conversation}", key=f"{user}_{conversation}"):
#                 view_conversation(user, conversation)

# def view_conversation(user, conversation):
#     filepath = os.path.join("conversations", user, conversation)
#     with open(filepath, 'r') as f:
#         messages = json.load(f)
#     st.subheader(f"Conversation: {conversation}")
#     for message in messages:
#         with st.chat_message(message["role"]):
#             st.write(message["content"])

def admin_page():
    st.title("Admin Dashboard")

    admin_function = st.selectbox(
        "Choose Admin Function",
        ["Show Users", "Create User", "Update User", "Delete User", "View All Conversations"]
    )

    if admin_function == "Show Users":
        show_users()
    elif admin_function == "Create User":
        create_user_form()
    elif admin_function == "Update User":
        update_user_form()
    elif admin_function == "Delete User":
        delete_user_form()
    elif admin_function == "View All Conversations":
        view_all_conversations()

# def view_all_conversations():
#     st.header("All User Conversations")
#     conversations = list_all_conversations()
    
#     # Crear una lista de todas las conversaciones con formato "usuario: conversación"
#     all_conversations = [f"{user}: {conv}" for user, user_conversations in conversations.items() for conv in user_conversations]
    
#     # Usar un selectbox para mostrar todas las conversaciones
#     selected_conversation = st.selectbox("Select a conversation to view", all_conversations)
    
#     if selected_conversation:
#         # Separar el usuario y la conversación seleccionada
#         user, conversation = selected_conversation.split(": ")
#         view_conversation(user, conversation)

def view_all_conversations():
    st.header("All User Conversations")
    conversations = list_all_conversations()
    
    # Crear una lista de todas las conversaciones con formato "usuario: conversación"
    all_conversations = ["Select a conversation"] + [f"{user}: {conv}" for user, user_conversations in conversations.items() for conv in user_conversations]
    
    # Usar un selectbox para mostrar todas las conversaciones
    selected_conversation = st.selectbox("Select a conversation to view", all_conversations)
    
    if selected_conversation != "Select a conversation":
        # Separar el usuario y la conversación seleccionada
        user, conversation = selected_conversation.split(": ")
        view_conversation(user, conversation)
    else:
        st.write("Please select a conversation to view its contents.")
        
        # Mostrar un resumen de las conversaciones disponibles
        st.subheader("Available Conversations:")
        for user, user_conversations in conversations.items():
            st.write(f"**{user}**: {len(user_conversations)} conversation(s)")

def view_conversation(user, conversation):
    filepath = os.path.join("conversations", user, conversation)
    with open(filepath, 'r') as f:
        messages = json.load(f)
    st.subheader(f"Conversation: {conversation}")
    for message in messages:
        with st.chat_message(message["role"]):
            st.write(message["content"])

def list_all_conversations():
    conversations = {}
    conversations_dir = "conversations"
    
    # Recorrer el directorio de conversaciones
    for user in os.listdir(conversations_dir):
        user_dir = os.path.join(conversations_dir, user)
        if os.path.isdir(user_dir):
            conversations[user] = []
            # Listar todas las conversaciones del usuario
            for conversation in os.listdir(user_dir):
                if conversation.endswith('.json'):  # Asumimos que las conversaciones se guardan como archivos JSON
                    conversations[user].append(conversation)
    
    return conversations
            
            
# def create_user_form():
#     st.header("Create New User")
#     new_email = st.text_input("Email")
#     new_password = st.text_input("Temporary Password", type="password")
#     new_nickname = st.text_input("Nickname")
#     is_admin = st.checkbox("Is Admin")
#     if st.button("Create User"):
#         success, message = create_user(new_email, new_password, new_nickname, is_admin)
#         if success:
#             st.success(message)
#         else:
#             st.error(message)

def update_user_form():
    st.header("Update User")
    update_username = st.text_input("Username to update")
    update_nickname = st.text_input("New Nickname")
    is_admin = st.checkbox("Is Admin")
    if st.button("Update User"):
        attributes = [
            {'Name': 'nickname', 'Value': update_nickname},
            {'Name': 'custom:is_admin', 'Value': 'true' if is_admin else 'false'}
        ]
        success, message = update_user(update_username, attributes)
        if success:
            st.success(message)
        else:
            st.error(message)

# def delete_user_form():
#     st.header("Delete User")
#     delete_username = st.text_input("Username to delete")
#     if st.button("Delete User"):
#         success, message = delete_user(delete_username)
#         if success:
#             st.success(message)
#         else:
#             st.error(message)

# def show_users():
#     st.header("User List")
#     users = list_users()
#     for user in users:
#         email = next((attr['Value'] for attr in user['Attributes'] if attr['Name'] == 'email'), 'N/A')
#         nickname = next((attr['Value'] for attr in user['Attributes'] if attr['Name'] == 'nickname'), 'N/A')
#         is_admin = any(attr['Name'] == 'custom:is_admin' and attr['Value'].lower() in ['true', '1'] for attr in user['Attributes'])
#         st.write(f"Username: {user['Username']}, Email: {email}, Nickname: {nickname}, Status: {user['UserStatus']}, Admin: {is_admin}")
def show_users():
    st.header("User List")
    users = list_users()
    
    # Crear una lista de diccionarios con los datos de los usuarios
    user_data = []
    for user in users:
        user_dict = {
            'Username': user['Username'],
            'Email': next((attr['Value'] for attr in user['Attributes'] if attr['Name'] == 'email'), 'N/A'),
            'Nickname': next((attr['Value'] for attr in user['Attributes'] if attr['Name'] == 'nickname'), 'N/A'),
            'Status': user['UserStatus'],
            'Admin': any(attr['Name'] == 'custom:is_admin' and attr['Value'].lower() in ['true', '1'] for attr in user['Attributes'])
        }
        user_data.append(user_dict)
    
    # Crear el DataFrame
    df = pd.DataFrame(user_data)
    
    # Mostrar el DataFrame en Streamlit
    st.dataframe(df,use_container_width=True)
    
    # Opcionalmente, puedes agregar más visualizaciones o estadísticas
    st.write(f"Total users: {len(df)}")
    st.write(f"Admins: {df['Admin'].sum()}")
    
    # # Puedes agregar gráficos si lo deseas
    # st.bar_chart(df['Status'].value_counts())
    
# def create_user_form():
#     st.header("Create New User")
#     new_email = st.text_input("Email")
#     new_password = st.text_input("Temporary Password", type="password")
#     new_nickname = st.text_input("Nickname")
#     is_admin = st.checkbox("Is Admin")
#     if st.button("Create User"):
#         success, message = create_user(new_email, new_password, new_nickname, is_admin)
#         if success:
#             st.success(message)
#         else:
#             st.error(message)

# def delete_user_form():
#     st.header("Delete User")
#     delete_option = st.radio("Delete by", ("Username", "Email"))
#     if delete_option == "Username":
#         delete_identifier = st.text_input("Username to delete")
#     else:
#         delete_identifier = st.text_input("Email to delete")
#     if st.button("Delete User"):
#         success, message = delete_user(delete_identifier, by_email=(delete_option == "Email"))
#         if success:
#             st.success(message)
#         else:
#             st.error(message)

# def create_user(email, temporary_password, nickname, is_admin=False):
#     client = boto3.client('cognito-idp', region_name=REGION_NAME)
#     try:
#         user_attributes = [
#             {'Name': 'email', 'Value': email},
#             {'Name': 'email_verified', 'Value': 'true'},
#             {'Name': 'nickname', 'Value': nickname},
#             {'Name': 'custom:is_admin', 'Value': 'true' if is_admin else 'false'}
#         ]
#         response = client.admin_create_user(
#             UserPoolId=USER_POOL_ID,
#             Username=email,
#             UserAttributes=user_attributes,
#             TemporaryPassword=temporary_password,
#             MessageAction='SUPPRESS'
#         )
#         return True, "User created successfully"
#     except Exception as e:
#         return False, str(e)

# def create_user_form():
#     st.header("Create New User")
#     new_email = st.text_input("Email")
#     new_nickname = st.text_input("Nickname")
#     is_admin = st.checkbox("Is Admin")
#     send_invitation = st.checkbox("Send Invitation by Email")
#     generate_password = st.checkbox("Generate Temporary Password")
    
#     if st.button("Create User"):
#         success, message = create_user(new_email, new_nickname, is_admin, send_invitation, generate_password)
#         if success:
#             st.success(message)
#         else:
#             st.error(message)

# def delete_user_form():
#     st.header("Delete User")
#     delete_option = st.radio("Delete by", ("Username", "Email"))
#     if delete_option == "Username":
#         delete_identifier = st.text_input("Username to delete")
#     else:
#         delete_identifier = st.text_input("Email to delete")
#     if st.button("Delete User"):
#         success, message = delete_user(delete_identifier, by_email=(delete_option == "Email"))
#         if success:
#             st.success(message)
#         else:
#             st.error(message)

# def create_user(email, nickname, is_admin=False, send_invitation=False, generate_password=False):
#     client = boto3.client('cognito-idp', region_name=REGION_NAME)
#     try:
#         user_attributes = [
#             {'Name': 'email', 'Value': email},
#             {'Name': 'email_verified', 'Value': 'true'},
#             {'Name': 'nickname', 'Value': nickname},
#             {'Name': 'custom:is_admin', 'Value': 'true' if is_admin else 'false'}
#         ]
        
#         # Construcción del diccionario de parámetros
#         params = {
#             'UserPoolId': USER_POOL_ID,
#             'Username': email,
#             'UserAttributes': user_attributes,
#             'MessageAction': 'SUPPRESS' if not send_invitation else 'RESEND'
#         }

#         if not generate_password:
#             # Si el usuario desea proporcionar una contraseña temporal
#             temporary_password = st.text_input("Temporary Password", type="password")
#             params['TemporaryPassword'] = temporary_password

#         response = client.admin_create_user(**params)

#         return True, "User created successfully"
#     except Exception as e:
#         return False, str(e)
# def create_user_form():
#     st.header("Create New User")
#     new_email = st.text_input("Email")
#     new_nickname = st.text_input("Nickname")
#     is_admin = st.checkbox("Is Admin")
#     send_invitation = st.checkbox("Send Invitation by Email")
#     generate_password = st.checkbox("Generate Temporary Password")
    
#     if st.button("Create User"):
#         success, message = create_user(new_email, new_nickname, is_admin, send_invitation, generate_password)
#         if success:
#             st.success(message)
#         else:
#             st.error(message)

# def delete_user_form():
#     st.header("Delete User")
#     delete_option = st.radio("Delete by", ("Username", "Email"))
#     if delete_option == "Username":
#         delete_identifier = st.text_input("Username to delete")
#     else:
#         delete_identifier = st.text_input("Email to delete")
#     if st.button("Delete User"):
#         success, message = delete_user(delete_identifier, by_email=(delete_option == "Email"))
#         if success:
#             st.success(message)
#         else:
#             st.error(message)

# def create_user(email, nickname, is_admin=False, send_invitation=False, generate_password=False):
#     client = boto3.client('cognito-idp', region_name=REGION_NAME)
#     try:
#         user_attributes = [
#             {'Name': 'email', 'Value': email},
#             {'Name': 'email_verified', 'Value': 'true'},
#             {'Name': 'nickname', 'Value': nickname},
#             {'Name': 'custom:is_admin', 'Value': 'true' if is_admin else 'false'}
#         ]
        
#         # Construcción del diccionario de parámetros
#         params = {
#             'UserPoolId': USER_POOL_ID,
#             'Username': email,
#             'UserAttributes': user_attributes
#         }

#         if generate_password:
#             # Si se selecciona generar una contraseña temporal
#             temporary_password = client.admin_set_user_password(
#                 UserPoolId=USER_POOL_ID,
#                 Username=email,
#                 Permanent=False
#             )
#             st.write(f"Generated Temporary Password: {temporary_password['Password']}")
#         else:
#             # Si el usuario proporciona una contraseña temporal
#             temporary_password = st.text_input("Temporary Password", type="password")
#             if temporary_password:
#                 params['TemporaryPassword'] = temporary_password
        
#         if send_invitation:
#             # No es necesario establecer 'MessageAction': 'RESEND' para enviar una invitación a un nuevo usuario
#             params['DesiredDeliveryMediums'] = ['EMAIL']

#         response = client.admin_create_user(**params)

#         return True, "User created successfully"
#     except Exception as e:
#         return False, str(e)

# def create_user_form():
#     st.header("Create New User")
#     new_email = st.text_input("Email")
#     new_nickname = st.text_input("Nickname")
#     is_admin = st.checkbox("Is Admin")
#     send_invitation = st.checkbox("Send Invitation by Email")
    
#     # Mostrar la opción de generar contraseña solo si no se selecciona enviar la invitación
#     if not send_invitation:
#         generate_password = st.checkbox("Generate Temporary Password")
#     else:
#         generate_password = False

#     if st.button("Create User"):
#         success, message = create_user(new_email, new_nickname, is_admin, send_invitation, generate_password)
#         if success:
#             st.success(message)
#         else:
#             st.error(message)

def delete_user_form():
    st.header("Delete User")
    delete_option = st.radio("Delete by", ("Username", "Email"))
    if delete_option == "Username":
        delete_identifier = st.text_input("Username to delete")
    else:
        delete_identifier = st.text_input("Email to delete")
    if st.button("Delete User"):
        success, message = delete_user(delete_identifier, by_email=(delete_option == "Email"))
        if success:
            st.success(message)
        else:
            st.error(message)

# def create_user(email, nickname, is_admin=False, send_invitation=False, generate_password=False):
#     client = boto3.client('cognito-idp', region_name=REGION_NAME)
#     try:
#         user_attributes = [
#             {'Name': 'email', 'Value': email},
#             {'Name': 'email_verified', 'Value': 'true'},
#             {'Name': 'nickname', 'Value': nickname},
#             {'Name': 'custom:is_admin', 'Value': 'true' if is_admin else 'false'}
#         ]
        
#         # Construcción del diccionario de parámetros
#         params = {
#             'UserPoolId': USER_POOL_ID,
#             'Username': email,
#             'UserAttributes': user_attributes
#         }

#         if not send_invitation:
#             # Si el usuario desea proporcionar o generar una contraseña temporal
#             if generate_password:
#                 # Generar una contraseña temporal
#                 temporary_password = client.admin_set_user_password(
#                     UserPoolId=USER_POOL_ID,
#                     Username=email,
#                     Permanent=False
#                 )
#                 st.write(f"Generated Temporary Password: {temporary_password['Password']}")
#             else:
#                 # Pedir al usuario que proporcione una contraseña temporal
#                 temporary_password = st.text_input("Temporary Password", type="password")
#                 if not temporary_password:
#                     return False, "Temporary Password is required if not sending an invitation."
#                 params['TemporaryPassword'] = temporary_password
        
#         if send_invitation:
#             # Enviar invitación por correo electrónico
#             params['DesiredDeliveryMediums'] = ['EMAIL']

#         response = client.admin_create_user(**params)

#         return True, "User created successfully"
#     except Exception as e:
#         return False, str(e)

 
def create_user_form():
    st.header("Create New User")
    
    # Obtener entradas del formulario
    new_email = st.text_input("Email")
    new_nickname = st.text_input("Nickname")
    is_admin = st.checkbox("Is Admin")
    
    # Checkbox para enviar invitación por email
    send_invitation = st.checkbox("Send Invitation by Email")

    # Condicional para mostrar la opción de generar una contraseña temporal
    if not send_invitation:
        generate_password = st.checkbox("Generate Temporary Password")
    else:
        generate_password = False

    # Capturar la contraseña temporal solo si no se selecciona 'send_invitation'
    temporary_password = ""
    if not send_invitation and not generate_password:
        temporary_password = st.text_input("Temporary Password", type="password")

    # Botón para crear el usuario
    if st.button("Create User"):
        success, message = create_user(new_email, new_nickname, is_admin, send_invitation, generate_password, temporary_password)
        if success:
            st.success(message)
        else:
            st.error(message)

def create_user(email, nickname, is_admin=False, send_invitation=False, generate_password=False, temporary_password=""):
    client = boto3.client('cognito-idp', region_name=REGION_NAME)
    try:
        user_attributes = [
            {'Name': 'email', 'Value': email},
            {'Name': 'email_verified', 'Value': 'true'},
            {'Name': 'nickname', 'Value': nickname},
            {'Name': 'custom:is_admin', 'Value': 'true' if is_admin else 'false'}
        ]
        
        # Construcción del diccionario de parámetros
        params = {
            'UserPoolId': USER_POOL_ID,
            'Username': email,
            'UserAttributes': user_attributes
        }

        if not send_invitation:
            if generate_password:
                response = client.admin_create_user(**params)
                # Se genera una contraseña temporal automática
                st.write("Cognito generará una contraseña temporal y la enviará al usuario.")
            else:
                # Si el usuario proporciona una contraseña temporal
                if temporary_password:
                    params['TemporaryPassword'] = temporary_password
                else:
                    return False, "Temporary Password is required if not sending an invitation."
        
        if send_invitation:
            # Enviar invitación por correo electrónico
            params['DesiredDeliveryMediums'] = ['EMAIL']
            response = client.admin_create_user(**params)

        return True, "User created successfully"
    except Exception as e:
        return False, str(e)
    
def delete_user(identifier, by_email=False):
    client = boto3.client('cognito-idp', region_name=REGION_NAME)
    try:
        if by_email:
            # Primero, busca el usuario por email
            response = client.list_users(
                UserPoolId=USER_POOL_ID,
                Filter=f'email = "{identifier}"'
            )
            if not response['Users']:
                return False, "User not found"
            username = response['Users'][0]['Username']
        else:
            username = identifier
        
        response = client.admin_delete_user(
            UserPoolId=USER_POOL_ID,
            Username=username
        )
        return True, "User deleted successfully"
    except Exception as e:
        return False, str(e)
    
def show_session_state():
    st.sidebar.header("Session State (Debug)")
    for key, value in st.session_state.items():
        st.sidebar.text(f"{key}: {value}")

def main():
    init_session_state()

    # Siempre mostrar el estado de la sesión para depuración
    # show_session_state()

    if not st.session_state.authenticated:
        if st.session_state.awaiting_new_password:
            new_password_page()
        else:
            login_page()
    else:
        pages = ["Chat", "Admin"] if st.session_state.get('is_admin', False) else ["Chat"]
        page = st.sidebar.radio("Navigation", pages)
        
        if page == "Chat":
            chatbot_page()
        elif page == "Admin":
            if st.session_state.get('is_admin', False):
                admin_page()
            else:
                st.error("You don't have permission to access the admin page.")
                chatbot_page()
    
    # if st.sidebar.button("Logout", key="logout-button"):
    #     logout()

def login(email, password):
    client = boto3.client('cognito-idp', region_name=REGION_NAME)
    secret_hash = get_secret_hash(email)
    try:
        response = client.initiate_auth(
            ClientId=CLIENT_ID,
            AuthFlow='USER_PASSWORD_AUTH',
            AuthParameters={
                'USERNAME': email,
                'PASSWORD': password,
                'SECRET_HASH': secret_hash
            }
        )

        if 'ChallengeName' in response and response['ChallengeName'] == 'NEW_PASSWORD_REQUIRED':
            st.session_state.session = response['Session']
            st.session_state.awaiting_new_password = True
            st.session_state.email = email
            st.session_state.user_attributes = json.loads(response['ChallengeParameters']['userAttributes'])
            st.rerun()
        
        st.session_state.authenticated = True
        st.session_state.token = response['AuthenticationResult']['IdToken']
        st.session_state.awaiting_new_password = False
        
        # Get user info and check if admin
        user_info = client.get_user(AccessToken=response['AuthenticationResult']['AccessToken'])
        st.session_state.user_name = "Usuario"
        st.session_state.is_admin = False
        # print (user_info['UserAttributes'])
        for attribute in user_info['UserAttributes']:
            if attribute['Name'] == 'name':
                st.session_state.user_name = attribute['Value']
            elif attribute['Name'] == 'email':
                st.session_state.user_name = attribute['Value'].split('@')[0]
            elif attribute['Name'] == 'custom:is_admin':
                # Check for both string and int representations
                st.session_state.is_admin = attribute['Value'].lower() in ['true', '1']
        
        # print(f"Login successful. Is admin: {st.session_state.is_admin}")  # Debug print
        return True, "Login successful"
    
    except Exception as e:
        print(f"Error during login: {str(e)}")
        return False, f"An unexpected error occurred: {str(e)}"
    
if __name__ == "__main__":
    main()