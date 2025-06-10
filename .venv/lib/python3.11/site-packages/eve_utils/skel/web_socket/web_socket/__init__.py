import logging
from flask import Flask, render_template
from log_trace.decorators import trace
from flask_socketio import send, emit


LOG = logging.getLogger('web_socket')
SOCKET = None


@trace
def initialize(app, socket):
    global SOCKET
    SOCKET = socket

    @app.route('/_ws')
    def web_socket():
        return render_template('ws.html', sync_mode=socket.async_mode)

    # TODO: remove this route (and templates/chat.html) after testing to confirm sockets are working
    @app.route('/_ws/chat')
    def chat_room():
        return render_template('chat.html')

    add_events(socket)


@trace
def add_events(socket):
    # TODO: replace this event handler with your own (or with 'pass')
    @socket.on('message')
    def handle_message(data):
        emit('message', data)
        LOG.info(f'Received message: {data}')


# TODO: replace with your send/emit actions (or remove)
def broadcast_message(message):
    LOG.info(f'Broadcasting to socket: {message}')
    SOCKET.emit('message', message)
