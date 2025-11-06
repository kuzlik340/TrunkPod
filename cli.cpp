#include <iostream>
#include <string_view>

extern bool debug_output;
static constexpr std::string_view logo[] = {
    R"(    __  __                       ____       _     __          )",
    R"(   / / / /___  ____  ___  __  __/ __ )_____(_)___/ /___ ____  )",
    R"(  / /_/ / __ \/ __ \/ _ \/ / / / __  / ___/ / __  / __ `/ _ \ )",
    R"( / __  / /_/ / / / /  __/ /_/ / /_/ / /  / / /_/ / /_/ /  __/ )",
    R"(/_/ /_/\____/_/ /_/\___/\__, /_____/_/  /_/\__,_/\__, /\___/  )",
    R"(                       /____/                   /____/        )",
};

void print_logo() {
    for (auto line : logo) std::cout << line << '\n';
}

void prompt_loop() {
    std::string cmd;
    while(true){
        std::cout << "HoneyBridge > " << std::flush;

        if (!std::getline(std::cin, cmd)) {
            std::cout << "\nQuitting due to error in getting user input." << std::endl;
            break; 
        }

        if (cmd.empty()) continue;

        if (cmd == "exit" || cmd == "quit") {
            std::cout << "Quitting\n";
            // TODO stop other threads
            //break;
            continue;
        }

        if (cmd == "help") {
            std::cout << "Available commands:\n"
                      << "  table arp show\n"
                      << "  table honeybridge show\n"
                      << "  help\n"
                      << "  exit | quit\n";
            continue;
        }

        if (cmd == "table arp show") {
            // TODO: replace with your real ARP print
            std::cout << "[ARP TABLE]\n";
            print_arp_table();
            continue;
        }
        
        if (cmd == "table honeybridge show") {
            // TODO: replace with your real HoneyBridge table print
            std::cout << "[HONEYBRIDGE TABLE]\n";
            // print_honeybridge_table();
            continue;
        }
        if (cmd == "debug") {
            // TODO: replace with your real HoneyBridge table print
            std::cout << "Debug output enabled" << std::endl;
            debug_output = true;
            // print_honeybridge_table();
            continue;
        }
    }

    
}
