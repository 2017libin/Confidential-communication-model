from Crypto.Hash import SHA256

# 以字节的形式读文件  
def read_file_by_byte(filename:str):
    f = open(filename, 'rb+')
    content = f.read()
    f.close()

# 发送数据：
def send(filename:str):
    
if __name__ == "__main__":
    read_file("test")