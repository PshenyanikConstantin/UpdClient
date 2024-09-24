#include "UdpClient.h"
#include <algorithm>

UdpClient::UdpClient(boost::asio::io_context& io_context, ClientSettings client_settings)
    : socket_(io_context, udp::endpoint(udp::v4(), 0))
    , protocol_version_(client_settings.protocol_version)
    , elements_amount_(client_settings.elements_amount)
    , value_(client_settings.value) {
    boost::asio::socket_base::receive_buffer_size recv_option(client_settings.elements_amount);
    socket_.set_option(recv_option);
    udp::resolver resolver(io_context);
    endpoints_ = resolver.resolve(udp::v4(), client_settings.ip_address, std::to_string(client_settings.port));
}

UdpClient::~UdpClient() {
    socket_.close();
}

void UdpClient::send_handshake() {
    request_message_.clear();
    nlohmann::json json_message = {
        {"type", "HANDSHAKE"},
        {"protocol_version", protocol_version_}
    };

    request_message_ = json_message.dump();
    write_to_log("Handshake sent to server.");

    socket_.async_send_to(boost::asio::buffer(request_message_), *endpoints_.begin(),
        [this](boost::system::error_code ec, std::size_t bytes_recvd) {
            if (!ec && bytes_recvd > 0) {
                handshake_handler();
            }
        });
}

void UdpClient::handshake_handler() {
    socket_.async_receive_from(boost::asio::buffer(receiver_buffer_), receiver_endpoint_,
        [this](boost::system::error_code error_code, std::size_t bytes_received) {
            if (!error_code && bytes_received > 0) {
                parse_handshake(bytes_received);
            }
        });
}

void UdpClient::parse_handshake(const std::size_t bytes_received) {
    try {
        write_to_log("Handshake received from server.");
        std::string handshake_message(receiver_buffer_.data(), bytes_received);
        nlohmann::json handshake_message_json = nlohmann::json::parse(handshake_message);
        if (handshake_message_json["type"].get<std::string>() == "HANDSHAKE") {
            std::string message = handshake_message_json["error_message"].get<std::string>();
            if (message.empty()) {
                send_request();
            }
            else {
                write_to_log("Error from server: " + message);
            }
        }
        else {
            write_to_log("Invalid handshake format from server.");
        }
    }
    catch (nlohmann::json::parse_error& e) {
        write_to_log("Can't parse message. " + std::string(e.what()));
    }
}

void UdpClient::send_request() {
    request_message_.clear();
    nlohmann::json json_message = {
        {"type", "REQUEST"},
        {"element_amount", elements_amount_},
        {"value", value_}
    };

    request_message_ = json_message.dump();

    socket_.async_send_to(boost::asio::buffer(request_message_), *endpoints_.begin(),
        [this](boost::system::error_code error_code, std::size_t bytes_received) {
            if (!error_code && bytes_received > 0) {
                received_elements_.reserve(elements_amount_);
                receive_response();
            }
        });
}

void UdpClient::receive_response() {
    chunk_.fill(0.0);
    socket_.async_receive_from(boost::asio::buffer(chunk_), receiver_endpoint_,
        [this](boost::system::error_code error_code, std::size_t bytes_received) {
            if (!error_code && bytes_received > 0) {
                std::size_t elements_amount = bytes_received / sizeof(double);
                received_elements_.insert(received_elements_.end(), chunk_.begin(), chunk_.begin() + elements_amount);
                if (received_elements_.size() != elements_amount_) {
                    receive_response();
                }
                else {
                    std::sort(received_elements_.begin(), received_elements_.end(), std::less<double>());
                    save_to_file();
                }
            }
        });
}

void UdpClient::save_to_file() {
    std::ofstream out_file("response.bin", std::ios::out | std::ios::binary | std::ios::trunc);

    if (out_file.is_open()) {
        write_to_log("File response.bin is opened.");
        out_file.write(reinterpret_cast<const char*>(received_elements_.data()), received_elements_.size() * sizeof(double));
        out_file.close();
        write_to_log("Array saved to output.bin in binary format");
    }
    else {
        write_to_log("Unable to open file response.bin");
    }
}

void UdpClient::write_to_log(const std::string& message) {
    std::ofstream log_file("log.txt", std::ios_base::app);
    if (log_file.is_open()) {
        log_file << message << std::endl;
    }
    else {
        std::cerr << "Unable to open log file" << std::endl;
    }
}