#include "UdpClient.h"

int main() {
    try {
        std::ifstream json_file_stream("ClientSettings.json");
        nlohmann::json json_data = nlohmann::json::parse(json_file_stream);
        ClientSettings client_settings;
        client_settings.Parse(json_data);

        boost::asio::io_context io_context;
        UdpClient client(io_context, client_settings);
        client.send_handshake();
        io_context.run();
    }
    catch (std::exception& e) {
        std::cerr << "Exception: " << e.what() << std::endl;
    }

    return 0;
}