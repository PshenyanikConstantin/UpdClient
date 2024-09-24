#pragma once
#include <boost/asio.hpp>
#include <nlohmann/json.hpp>
#include <iostream>
#include <fstream>

using boost::asio::ip::udp;

struct ClientSettings {
    std::string ip_address = {};
    unsigned int port = 0;
    unsigned int protocol_version = 0;
    unsigned int elements_amount = 0;
    double value = 0.0;

    void Parse(nlohmann::json JsonData) {
        ip_address = JsonData["ip_addres"].get<std::string>();
        port = JsonData["port"].get<unsigned int>();
        protocol_version = JsonData["protocol_version"].get<unsigned int>();
        elements_amount = JsonData["elements_amount"].get<unsigned int>();
        value = JsonData["value"].get<double>();
    }
};

class UdpClient {
public:
    UdpClient(boost::asio::io_context& io_context, ClientSettings client_settings);
    ~UdpClient();

    void send_handshake();

private:
    void handshake_handler();
    void parse_handshake(const std::size_t bytes_received);
    void send_request();
    void receive_response();
    void save_to_file();
    void write_to_log(const std::string& message);

private:
    const std::size_t chunk_size_ = 1024;
    udp::socket socket_;
    udp::endpoint receiver_endpoint_;
    udp::resolver::results_type endpoints_;
    std::string request_message_;
    std::array<char, 1024> receiver_buffer_;
    std::array<double, 1024> chunk_;
    
    unsigned int protocol_version_;
    unsigned int elements_amount_;
    double value_;

    std::vector<double> received_elements_;
};


