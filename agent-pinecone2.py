import streamlit as st
import tools
import json
import os
from datetime import datetime
import boto3
import hmac
import base64
import hashlib

# Configuración de AWS Cognito
USER_POOL_ID = 'us-east-1_DzVB7yQ87'
CLIENT_ID = 'm47hdqpevjk6hv6m7ul9jqonv'
CLIENT_SECRET = '18i75h8ho88rrkq2gnkg1f6amdm09ilt6g137iot4b897ttqa8ps'
REGION_NAME = 'us-east-1'

# Funciones auxiliares

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
    # st.title("Bienvenido 👋 ")
    st.markdown("<h1 style='text-align: center;'> BIENVENIDO</h1>", unsafe_allow_html=True)
    
    # buff, col, buff2 = st.beta_columns([1,3,1])

    # st.markdown("""
    # <style>
    #     .stTextInput > div > div > input {
    #         width: 100%;
    #     }
    # </style>
    # """, unsafe_allow_html=True)
    
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

def chatbot_page():
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

    # if st.sidebar.button("Logout"):
    #     st.session_state.authenticated = False
    #     st.session_state.email = None
    #     st.session_state.token = None
    #     st.session_state.user_name = None  # Limpiar el nombre de usuario al cerrar sesión
    #     st.session_state.awaiting_new_password = False
    #     st.session_state.clear()
    #     st.rerun()
     # Botón de Logout con color rojo
    if st.sidebar.button("Logout", key="logout-button"):
        logout()

# def chatbot_page():
#     # Aplicar estilo para todos los botones y específicamente para el botón de Logout
#     st.markdown("""
#     <style>
#         .stButton > button {
#             width: 100%;
#         }
#         .stButton > button#logout-button {
#             background-color: red;
#             color: white;
#         }
#     </style>
#     """, unsafe_allow_html=True)

#     # Obtener el nombre del usuario de la sesión
#     user_name = st.session_state.get('user_name', 'Usuario')
    
#     # Mostrar el saludo personalizado
#     st.markdown(f"<h1 style='text-align: center;'>¡Bienvenido, {user_name}! 👋</h1>", unsafe_allow_html=True)
#     st.markdown("<h2 style='text-align: center;'>🤖 Honne IA 3.0 Pinecone</h2>", unsafe_allow_html=True)

#     user_folder = f"conversations/{st.session_state.email.split('@')[0]}"
#     if not os.path.exists(user_folder):
#         os.makedirs(user_folder)

#     saved_conversations = [f for f in os.listdir(user_folder) if f.endswith('.json')]
    
#     if st.sidebar.button("Start New Conversation"):
#         start_new_conversation()

#     selected_conversation = st.sidebar.selectbox(
#         "Load or start a conversation",
#         ["New conversation"] + saved_conversations,
#         key="conversation_selector"
#     )
    
#     # Checkbox
#     show_references = st.sidebar.checkbox("Show References", value=True, key="show_references")

#     if selected_conversation == "New conversation":
#         if "messages" not in st.session_state or st.session_state.current_conversation != "New conversation":
#             start_new_conversation()
#     else:
#         if "current_conversation" not in st.session_state or st.session_state.current_conversation != selected_conversation:
#             st.session_state.messages = load_conversation(os.path.join(user_folder, selected_conversation))
#             st.session_state.current_conversation = selected_conversation
#             st.session_state.conversation_filename = selected_conversation

#     if "messages" in st.session_state:
#         for message in st.session_state.messages:
#             with st.chat_message(message["role"]):
#                 st.write(message["content"])

#     user_input = st.chat_input("Type your message here")

#     if user_input:
#         st.session_state.messages.append({"role": "user", "content": user_input})
        
#         assistant_response = process_llm_response(user_input, show_references)
#         st.session_state.messages.append({"role": "assistant", "content": assistant_response})

#         save_conversation(st.session_state.messages, os.path.join(user_folder, st.session_state.conversation_filename))
        
#         st.rerun()

#     # Botón de Logout con color rojo
#     if st.sidebar.button("Logout", key="logout-button"):
#         st.session_state.authenticated = False
#         st.session_state.email = None
#         st.session_state.token = None
#         st.session_state.user_name = None  # Limpiar el nombre de usuario al cerrar sesión
#         st.session_state.awaiting_new_password = False
#         st.session_state.clear()
#         st.rerun()


# def chatbot_page():
#     # Aplicar estilo para todos los botones y específicamente para el botón de Logout
#     st.markdown("""
#         <style>
#         .stButton>button {
#             color: #ffffff;
#             background-color: #4CAF50;
#             border: none;
#         }
#         .stButton>button:hover {
#             background-color: #45a049;
#         }
#         .logout-button>button {
#             background-color: #ff0000 !important;
#         }
#         .logout-button>button:hover {
#             background-color: #cc0000 !important;
#         }
#         </style>
#         """, unsafe_allow_html=True)
    
#     # Obtener el nombre del usuario de la sesión
#     user_name = st.session_state.get('user_name', 'Usuario')
    
#     # Mostrar el saludo personalizado
#     st.markdown(f"<h1>¡Bienvenido, {user_name}! 👋</h1>", unsafe_allow_html=True)
#     st.markdown("<h2>🤖 Honne IA 3.0 Pinecone</h2>", unsafe_allow_html=True)
    
#     user_folder = f"conversations/{st.session_state.email.split('@')[0]}"
#     if not os.path.exists(user_folder):
#         os.makedirs(user_folder)
    
#     saved_conversations = [f for f in os.listdir(user_folder) if f.endswith('.json')]
    
#     if st.sidebar.button("Start New Conversation"):
#         start_new_conversation()
    
#     selected_conversation = st.sidebar.selectbox(
#         "Load or start a conversation",
#         ["New conversation"] + saved_conversations,
#         key="conversation_selector"
#     )
    
#     # Checkbox
#     show_references = st.sidebar.checkbox("Show References", value=True, key="show_references")
    
#     if selected_conversation == "New conversation":
#         if "messages" not in st.session_state or st.session_state.current_conversation != "New conversation":
#             start_new_conversation()
#     else:
#         if "current_conversation" not in st.session_state or st.session_state.current_conversation != selected_conversation:
#             st.session_state.messages = load_conversation(os.path.join(user_folder, selected_conversation))
#             st.session_state.current_conversation = selected_conversation
#             st.session_state.conversation_filename = selected_conversation
    
#     if "messages" in st.session_state:
#         for message in st.session_state.messages:
#             with st.chat_message(message["role"]):
#                 st.write(message["content"])
    
#     user_input = st.chat_input("Type your message here")
    
#     if user_input:
#         st.session_state.messages.append({"role": "user", "content": user_input})
        
#         assistant_response = process_llm_response(user_input, show_references)
#         st.session_state.messages.append({"role": "assistant", "content": assistant_response})
        
#         save_conversation(st.session_state.messages, os.path.join(user_folder, st.session_state.conversation_filename))
        
#         st.rerun()
    
    # # Botón de Logout con color rojo
    # if st.sidebar.button("Logout", key="logout-button", on_click=logout):
    #     pass

def logout():
    st.session_state.authenticated = False
    st.session_state.email = None
    st.session_state.token = None
    st.session_state.user_name = None  # Limpiar el nombre de usuario al cerrar sesión
    st.session_state.awaiting_new_password = False
    st.session_state.clear()
    st.rerun()

def main():
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

if __name__ == "__main__":
    main()