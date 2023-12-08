import hashlib
import logging
import argparse
import time
import os
from logging.handlers import TimedRotatingFileHandler
from socket import *
import json
import struct
import threading
import tqdm
import sys

logger = logging.getLogger('')
# Const Value
OP_SAVE, OP_DELETE, OP_GET, OP_UPLOAD, OP_DOWNLOAD, OP_BYE, OP_LOGIN, OP_ERROR = 'SAVE', 'DELETE', 'GET', 'UPLOAD', 'DOWNLOAD', 'BYE', 'LOGIN', "ERROR"
TYPE_FILE, TYPE_DATA, TYPE_AUTH, DIR_EARTH = 'FILE', 'DATA', 'AUTH', 'EARTH'
FIELD_OPERATION, FIELD_DIRECTION, FIELD_TYPE, FIELD_USERNAME, FIELD_PASSWORD, FIELD_TOKEN = 'operation', 'direction', 'type', 'username', 'password', 'token'
FIELD_KEY, FIELD_SIZE, FIELD_TOTAL_BLOCK, FIELD_MD5, FIELD_BLOCK_SIZE = 'key', 'size', 'total_block', 'md5', 'block_size'
FIELD_STATUS, FIELD_STATUS_MSG, FIELD_BLOCK_INDEX = 'status', 'status_msg', 'block_index'
DIR_REQUEST, DIR_RESPONSE = 'REQUEST', 'RESPONSE'
FILE_PATH = 'file_path'


def _argparse():
    parse = argparse.ArgumentParser()
    parse.add_argument("--server_ip", default='127.0.0.1', action='store', required=False, dest="server_ip",
                       help="The IP address of the server. Default localhost.")
    parse.add_argument("--id", default='0', action='store', required=False, dest="id",
                       help="Student ID. Default is 0.")
    parse.add_argument("--f", action='store', required=True, dest="file_path",
                       help="The path of the file to be sent.")
    return parse.parse_args()


def get_file_md5(filename):
    """
    Get MD5 value for big file
    :param filename:
    :return:
    """
    m = hashlib.md5()
    with open(filename, 'rb') as fid:
        while True:
            d = fid.read(2048)
            if not d:
                break
            m.update(d)
    return m.hexdigest()



def get_time_based_filename(ext, prefix='', t=None):
    """
    Get a filename based on time
    :param ext: ext name of the filename
    :param prefix: prefix of the filename
    :param t: the specified time if necessary, the default is the current time. Unix timestamp
    :return:
    """
    ext = ext.replace('.', '')
    if t is None:
        t = time.time()
    if t > 4102464500:
        t = t / 1000
    return time.strftime(f"{prefix}%Y%m%d%H%M%S." + ext, time.localtime(t))


def get_tcp_packet(conn):
    """
    Receive a complete TCP "packet" from a TCP stream and get the json data and binary data.
    :param conn: the TCP connection
    :return:
        json_data
        bin_data
    """
    bin_data = b''
    while len(bin_data) < 8:
        data_rec = conn.recv(8)
        if data_rec == b'':
            time.sleep(0.01)
        if data_rec == b'':
            return None, None
        bin_data += data_rec
    data = bin_data[:8]
    bin_data = bin_data[8:]
    j_len, b_len = struct.unpack('!II', data)
    while len(bin_data) < j_len:
        data_rec = conn.recv(j_len)
        if data_rec == b'':
            time.sleep(0.01)
        if data_rec == b'':
            return None, None
        bin_data += data_rec
    j_bin = bin_data[:j_len]

    try:
        json_data = json.loads(j_bin.decode())
    except Exception as ex:
        return None, None

    bin_data = bin_data[j_len:]
    while len(bin_data) < b_len:
        data_rec = conn.recv(b_len)
        if data_rec == b'':
            time.sleep(0.01)
        if data_rec == b'':
            return None, None
        bin_data += data_rec
    return json_data, bin_data

def check_upload_error(json_data, cliSocket):
    """
    Detect and handle the error from server when uploading
    :param json_data:
    :param cliSocket:
    :return:
    """

    global logger, return_md5
    if json_data[FIELD_STATUS] == 200:
        if FIELD_MD5 in json_data:
            logger.info(f"--> The whole file '{json_data[FIELD_KEY]}' has been uploaded")
            return_md5 = str(json_data[FIELD_MD5])
    else:
        logger.error(f"--> ERROR, {json_data[FIELD_STATUS]} : '{json_data[FIELD_STATUS_MSG]}' ")
        error_code = json_data[FIELD_STATUS]
        if error_code == 400:
            print("Compulsory field is missing.")
        elif error_code == 401:
            print("Password error for login.")
        elif error_code == 402:
            print("The key is existing.")
        elif error_code == 403:
            print("No token or token is wrong.")
        elif error_code == 404:
            print("Cannot find the key.")
        elif error_code == 405:
            print("The block_index is over the maximum block number.")
        elif error_code == 406:
            print("The size for uploading does not match the required block_size.")
        elif error_code == 407:
            print("Wrong direction.")
        elif error_code == 408:
            print("Wrong operation.")
        elif error_code == 409:
            print("Type is not allowed.")
        elif error_code == 410:
            print("Field is missing.")
        cliSocket.close()
        print("Mission fail, client close.")
        sys.exit()

def set_logger(logger_name):
    """
    Create a logger
    :param logger_name: 日志名称
    :return: logger
    """
    logger_ = logging.getLogger(logger_name)  # 不加名称设置root logger
    logger_.setLevel(logging.INFO)

    formatter = logging.Formatter(
        '\033[0;34m%s\033[0m' % '%(asctime)s-%(name)s[%(levelname)s] %(message)s @ %(filename)s[%(lineno)d]',
        datefmt='%Y-%m-%d %H:%M:%S')

    # --> LOG FILE
    logger_file_name = get_time_based_filename('log')
    os.makedirs(f'CW1/log/{logger_name}', exist_ok=True)

    fh = TimedRotatingFileHandler(filename=f'CW1/log/{logger_name}/log', when='D', interval=1, backupCount=1)
    fh.setFormatter(formatter)

    fh.setLevel(logging.INFO)

    # --> SCREEN DISPLAY
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    ch.setFormatter(formatter)

    logger_.propagate = False
    logger_.addHandler(ch)
    logger_.addHandler(fh)
    return logger_


def make_request_packet(operation, data_type, json_data, bin_data=None):
    """
    Make a packet for request
    :param operation: [SAVE, DELETE, GET, UPLOAD, DOWNLOAD, BYE, LOGIN]
    :param data_type: [FILE, DATA, AUTH]
    :param json_data
    :param bin_data
    :return:
    """
    json_data[FIELD_OPERATION] = operation
    json_data[FIELD_DIRECTION] = DIR_REQUEST
    json_data[FIELD_TYPE] = data_type
    return make_packet(json_data, bin_data)


def make_packet(json_data, bin_data=None):
    """
    Make a packet following the STEP protocol.
    Any information or data for TCP transmission has to use this function to get the packet.
    :param json_data:
    :param bin_data:
    :return:
        The complete binary packet
    """
    j = json.dumps(dict(json_data), ensure_ascii=False)
    j_len = len(j)
    if bin_data is None:
        return struct.pack('!II', j_len, 0) + j.encode()
    else:
        return struct.pack('!II', j_len, len(bin_data)) + j.encode() + bin_data


def get_token_auth(client_socket, data):
    """
       Authorize the user to get the token.
       :param client_socket:
       :param data:
       :return: the authorization token
    """
    client_socket.send(make_request_packet(OP_LOGIN, TYPE_AUTH, data))
    json_data, _ = get_tcp_packet(client_socket)
    json_data: dict
    check_upload_error(json_data,client_socket)
    token = json_data[FIELD_TOKEN]
    logger.info(f"Token received: {token}")
    return token


def get_upload_plan(client_socket, token, key, file_size):
    """
    Get the upload plan from the server.
    :param client_socket
    :param token
    :param key
    :param file_size
    :return: the upload plan from the server
    """
    data = {
        FIELD_TOKEN: token,
        FIELD_KEY: key,
        FIELD_SIZE: file_size
    }
    client_socket.send(make_request_packet(OP_SAVE, TYPE_FILE, data))
    json_data, _ = get_tcp_packet(client_socket)
    json_data: dict
    check_upload_error(json_data, client_socket)
    return json_data


md5_dict = {}
# 在代码的开头定义一个锁
lock = threading.Lock()
def upload_block(client_socket, token, key, start_block, end_block,block_size, file_size, path):
    with open(path, "rb") as file:
        for block_index in range(start_block,end_block):
            data = {
                FIELD_TOKEN: token,
                FIELD_KEY: key,
                FIELD_BLOCK_INDEX: block_index
            }
            file.seek(block_size * block_index)
            if block_size * (block_index + 1) < file_size:
                bin_data = file.read(block_size)
            else:
                bin_data = file.read(file_size - block_size * block_index)
            lock.acquire()
            client_socket.send(make_request_packet(OP_UPLOAD, TYPE_FILE, data, bin_data))
            json_data, _ = get_tcp_packet(client_socket)
            json_data: dict
            lock.release()
        # 使用锁确保对共享资源的安全访问
            with lock:
                if json_data is not None and json_data[FIELD_STATUS] == 200:
                    logger.info(json_data)
                    if FIELD_MD5 in json_data:
                        global md5
                        md5 = json_data[FIELD_MD5]
                else:
                    logger.warning(f"Error: error in uploading block {block_index}.")


def upload_file_thread(client_socket, upload_plan, token, key, file_size, path, num_threads):
    total_block = upload_plan[FIELD_TOTAL_BLOCK]
    block_size = upload_plan[FIELD_BLOCK_SIZE]
    md5 = ""
    threads = []
    blocks_per_thread = total_block // num_threads
    for i in range(num_threads):
        start_block = i * blocks_per_thread
        end_block = (i + 1) * blocks_per_thread if i < num_threads - 1 else total_block

        single_thread = threading.Thread(target=upload_block,
                                  args=(client_socket, token, key, start_block,end_block,block_size, file_size, path))
        single_thread.start()
        time.sleep(0.02)
        threads.append(single_thread)

    for thread in threads:
        thread.join()

    return md5




def upload_file(client_socket, upload_plan, token, key, file_size, path):
    """
    Upload a file to the server according to the upload plan.
    Each block is uploaded separately in the loop.
    :param client_socket
    :param upload_plan
    :param token
    :param key
    :param file_size
    :param path: file path
    :return:
    """
    total_block = upload_plan[FIELD_TOTAL_BLOCK]
    block_size = upload_plan[FIELD_BLOCK_SIZE]
    md5 = ""
    with open(path, "rb") as file:
        for block_index in range(total_block):
            data = {
                FIELD_TOKEN: token,
                FIELD_KEY: key,
                FIELD_BLOCK_INDEX: block_index
            }
            file.seek(block_size * block_index)
            if block_size * (block_index + 1) < file_size:
                bin_data = file.read(block_size)
            else:
                bin_data = file.read(file_size - block_size * block_index)
            client_socket.send(make_request_packet(OP_UPLOAD, TYPE_FILE, data, bin_data))
            json_data, _ = get_tcp_packet(client_socket)
            json_data: dict
            if json_data is not None and json_data[FIELD_STATUS] == 200:
                logger.info(json_data)
                if FIELD_MD5 in json_data:
                    md5 = json_data[FIELD_MD5]
            else:
                logger.warning("Error: error in uploading blocks.")
    return md5


def tcp_client_upload(server_ip, server_port, data, num_threads=1):
    """S
    TCP client upload: connect to a port through TCP and upload a file
    :param server_port
    :param data: data to be sent
    :param server_ip
    :return: None
    """
    global logger
    client_socket = socket(AF_INET, SOCK_STREAM)
    client_socket.connect((server_ip, int(server_port)))
    logger.info("Start connecting to the server...")
    logger.info("Request for token...")
    token = get_token_auth(client_socket, data)
    upload_plan = get_upload_plan(client_socket, token, data[FIELD_KEY], data[FIELD_SIZE])
    # md5 = upload_file(client_socket, upload_plan, token, data[FIELD_KEY], data[FIELD_SIZE], data[FILE_PATH])
    # if md5 == get_file_md5(data[FILE_PATH]):
    #     logger.info("Upload successfully! md5 is correct.")
    # else:
    #     logger.warning("Upload failed! md5 is not correct.")

    upload_file_thread(client_socket, upload_plan, token, data[FIELD_KEY], data[FIELD_SIZE], data[FILE_PATH], num_threads)
    if md5 == get_file_md5(data[FILE_PATH]):
        logger.info("Upload successfully! md5 is correct.")
    else:
        logger.warning("Upload failed! md5 is not correct.")

    client_socket.close()



def main():
    global logger
    logger = set_logger('CLIENT')
    parser = _argparse()
    server_ip = parser.server_ip
    student_id = parser.id
    path = parser.file_path
    server_port = "1379"
    data = {
        FIELD_USERNAME: student_id,
        FIELD_PASSWORD: hashlib.md5(student_id.encode()).hexdigest().lower(),
        FILE_PATH: path,
        FIELD_KEY: path.split('/')[-1],
        FIELD_SIZE: os.path.getsize(path)
    }
    tcp_client_upload(server_ip, server_port, data)


if __name__ == '__main__':
    main()
