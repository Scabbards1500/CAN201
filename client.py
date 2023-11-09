import hashlib
import logging
import argparse
import time
import os
from logging.handlers import TimedRotatingFileHandler
from socket import *
import json
import struct
import matplotlib.pyplot as plt

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
    Get a filename based on time 用于生成基于时间的文件名
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
    bin_data = b'' # 初始化一个二进制数据变量bin_data，用于存储从TCP连接中接收到的数据。
    while len(bin_data) < 8:  # 从TCP连接中接收数据，直到接收到的数据长度大于等于8字节。
        data_rec = conn.recv(8)
        if data_rec == b'': # 如果接收到的数据为空，则等待0.01秒后继续接收。
            time.sleep(0.01)
        if data_rec == b'': # 如果接收到的数据为空，则返回None, None。
            return None, None
        bin_data += data_rec
    data = bin_data[:8] # 从接收到的数据中取出前8字节，这8字节是一个二进制数据，用于存储json数据的长度和二进制数据的长度。
    bin_data = bin_data[8:]
    j_len, b_len = struct.unpack('!II', data) # 将这8字节的二进制数据解包，得到json数据的长度和二进制数据的长度。
    while len(bin_data) < j_len: # 从TCP连接中接收数据，直到接收到的数据长度大于等于json_len个字节。
        data_rec = conn.recv(j_len)
        if data_rec == b'':
            time.sleep(0.01)
        if data_rec == b'':
            return None, None
        bin_data += data_rec
    j_bin = bin_data[:j_len]

    try:
        json_data = json.loads(j_bin.decode()) # 将接收到的json数据解码为json格式。
    except Exception as ex:
        return None, None

    bin_data = bin_data[j_len:] # 从接收到的数据中取出json数据后面的数据，这些数据是二进制数据。
    while len(bin_data) < b_len:
        data_rec = conn.recv(b_len)
        if data_rec == b'':
            time.sleep(0.01)
        if data_rec == b'':
            return None, None
        bin_data += data_rec
    return json_data, bin_data


def set_logger(logger_name):
    """
    Create a logger 这个日志记录器可用于记录应用程序的日志信息，将日志信息输出到日志文件和控制台。
    :param logger_name: 日志名称
    :return: logger
    """
    logger_ = logging.getLogger(logger_name)  # 不加名称设置root logger 如果未提供名称，将创建根日志记录器。
    logger_.setLevel(logging.INFO)  # 然后设置该日志记录器的日志级别为INFO，表示它将记录INFO级别及更高级别的日志消息。

    formatter = logging.Formatter(   # 定义了日志消息的格式，包括时间戳、日志名称、日志级别、消息内容、以及文件名和行号等信息。这个格式可以自定义，根据需要进行调整。
        '\033[0;34m%s\033[0m' % '%(asctime)s-%(name)s[%(levelname)s] %(message)s @ %(filename)s[%(lineno)d]',
        datefmt='%Y-%m-%d %H:%M:%S')

    # --> LOG FILE 配置日志文件输出
    logger_file_name = get_time_based_filename('log')
    os.makedirs(f'log/{logger_name}', exist_ok=True)

    fh = TimedRotatingFileHandler(filename=f'log/{logger_name}/log', when='D', interval=1, backupCount=1)   # 按天切割日志文件。将日志信息写入一个按日期滚动的日志文件，并保留一份备份。日志文件的名称是基于时间的，并保存在以log_name为名称的文件夹中
    fh.setFormatter(formatter)  # 设置日志消息的格式

    fh.setLevel(logging.INFO)  # 设置日志级别为INFO，表示它将记录INFO级别及更高级别的日志消息。

    # --> SCREEN DISPLAY 配置屏幕显示输出
    ch = logging.StreamHandler()  # 除了写入日志文件外，函数还配置了将日志信息输出到控制台。它使用logging.StreamHandler来创建一个处理器，将日志信息显示在控制台。
    ch.setLevel(logging.INFO)
    ch.setFormatter(formatter)  # 设置日志消息的格式

    logger_.propagate = False # 防止日志信息被重复输出
    logger_.addHandler(ch)
    logger_.addHandler(fh)
    return logger_


def make_request_packet(operation, data_type, json_data, bin_data=None):
    """
    Make a packet for request 用于创建一个请求数据包，该数据包用于在某种应用程序或协议中发送请求操作。函数的目的是构造一个包含操作、数据类型、JSON数据和二进制数据的请求数据包.将请求相关的元数据添加到JSON数据中，并使用另一个函数构建最终的数据包。这可以提高代码的可读性和维护性，同时使请求数据包的创建更加一致和方便。
    :param operation: [SAVE, DELETE, GET, UPLOAD, DOWNLOAD, BYE, LOGIN]
    :param data_type: [FILE, DATA, AUTH]
    :param json_data
    :param bin_data
    :return:
    """
    json_data[FIELD_OPERATION] = operation  #  这是一个字符串参数，表示请求的操作类型。可能的操作类型包括"SAVE"、"DELETE"、"GET"、"UPLOAD"、"DOWNLOAD"、"BYE"和"LOGIN"，根据不同的应用或协议定义。
    json_data[FIELD_DIRECTION] = DIR_REQUEST  # 将数据方向设置为请求。
    json_data[FIELD_TYPE] = data_type  # 这是一个字符串参数，表示数据的类型。可能的数据类型包括"FILE"、"DATA"和"AUTH"，用于指示数据的不同用途或类型。
    return make_packet(json_data, bin_data)  # 调用make_packet函数，将json数据和二进制数据打包成一个完整的数据包。


def make_packet(json_data, bin_data=None):
    """
    Make a packet following the STEP protocol.用于创建一个二进制数据包，遵循所谓的"STEP protocol"
    Any information or data for TCP transmission has to use this function to get the packet. 将JSON数据和二进制数据组合成一个二进制数据包，以便在TCP传输中发送
    :param json_data:
    :param bin_data:
    :return:
        The complete binary packet
    """
    j = json.dumps(dict(json_data), ensure_ascii=False)  # 将JSON数据转换为字符串，以便在TCP传输中发送.因为JSON数据可能包含非ASCII字符，因此需要保留原始字符(如中文)。
    j_len = len(j)
    if bin_data is None: # 创建二进制数据包：根据是否提供了二进制数据，函数使用struct.pack函数创建一个二进制数据包。
        return struct.pack('!II', j_len, 0) + j.encode()  # 如果没有提供二进制数据，函数创建一个包含JSON数据长度和0长度的二进制包。如果提供了二进制数据，函数将包含JSON数据长度和二进制数据长度的二进制包。
    else:
        return struct.pack('!II', j_len, len(bin_data)) + j.encode() + bin_data


def get_token_auth(client_socket, data):
    """
       Authorize the user to get the token. 于在客户端与服务器之间进行身份验证，并获取授权令牌以进行后续操作。如果身份验证失败或服务器响应出现问题，函数会记录警告消息并退出
       :param client_socket:
       :param data:
       :return: the authorization token
    """
    client_socket.send(make_request_packet(OP_LOGIN, TYPE_AUTH, data)) # 通过TCP发送请求数据包，以便在服务器上进行身份验证。如果身份验证失败或服务器响应出现问题，函数会记录警告消息并退出。
    json_data, _ = get_tcp_packet(client_socket) # 从服务器接收响应数据包，以便获取授权令牌。如果服务器响应出现问题，函数会记录警告消息并退出。
    json_data: dict
    if json_data is None:
        logger.warning('Connection is closed by server.')
        exit()
    elif json_data[FIELD_STATUS] != 200 or FIELD_TOKEN not in json_data: # 函数首先检查响应中是否包含有效的JSON数据。如果没有有效的JSON数据，表示连接被服务器关闭，函数会记录警告消息并退出。如果存在JSON数据，函数将检查响应中的状态码（FIELD_STATUS）是否为200，表示成功。如果状态码不为200或者响应中没有授权令牌（FIELD_TOKEN），函数会记录警告消息并退出。
        logger.warning(f"Error: {json_data[FIELD_STATUS_MSG]}")
        exit()
    token = json_data[FIELD_TOKEN]  #：如果一切正常，函数从响应中提取授权令牌（FIELD_TOKEN）并返回它。此时，客户端已成功获得授权令牌用于后续身份验证或授权操作
    logger.info(f"Token received: {token}")
    return token


def get_upload_plan(client_socket, token, key, file_size):
    """
    Get the upload plan from the server. 用于向服务器发送请求以获取上传计划（upload plan）。上传计划通常包括有关上传文件的信息，如存储位置、上传令牌等。
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
    if json_data is None:
        logger.warning('Connection is closed by server.')
        exit()
    elif json_data[FIELD_STATUS] != 200:  # 函数首先检查响应中是否包含有效的JSON数据。如果没有有效的JSON数据，表示连接被服务器关闭，函数会记录警告消息并退出。如果存在JSON数据，函数将检查响应中的状态码（FIELD_STATUS）是否为200，表示成功。如果状态码不为200，函数会记录警告消息并退出。
        logger.warning(f"Error: {json_data[FIELD_STATUS_MSG]}")
        exit()
    return json_data


def upload_file(client_socket, upload_plan, token, key, file_size, path):
    """
    Upload a file to the server according to the upload plan. 用于根据上传计划将文件上传到服务器。上传过程会将文件分成多个块（blocks），每个块都会被单独上传。
    Each block is uploaded separately in the loop.
    :param client_socket
    :param upload_plan
    :param token
    :param key
    :param file_size
    :param path: file path
    :return:
    """
    total_block = upload_plan[FIELD_TOTAL_BLOCK]  #初始化变量：函数首先初始化一些变量，包括总块数、块大小和一个用于存储MD5哈希值的变量。
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
            if json_data is not None and json_data[FIELD_STATUS] == 200: #数检查响应中的状态码（FIELD_STATUS）。如果状态码为200，表示上传块成功，函数记录信息。如果响应中包含MD5哈希值（FIELD_MD5），则将其保存在md5变量中。如果上传块失败，函数记录警告消息。
                logger.info(json_data)
                if FIELD_MD5 in json_data:
                    md5 = json_data[FIELD_MD5]
            else:
                logger.warning("Error: error in uploading blocks.")
    return md5   #：函数返回MD5哈希值。


def tcp_client_upload(server_ip, server_port, data):
    """
    TCP client upload: connect to a port through TCP and upload a file 用于实现TCP客户端上传文件的完整流程，包括请求授权令牌、获取上传计划、上传文件块、验证文件完整性等操作。如果上传成功，客户端记录成功信息；如果上传失败，客户端记录警告信息。
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
    md5 = upload_file(client_socket, upload_plan, token, data[FIELD_KEY], data[FIELD_SIZE], data[FILE_PATH])
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
