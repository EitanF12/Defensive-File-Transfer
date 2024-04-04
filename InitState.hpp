#ifndef Init_HPP
#define Init_HPP

#include "State.hpp"
#include <string>

class InitState : public State {
public:
    InitState() = default;
    ~InitState();
    std::string createMessage(const std::string& payload) override {}; // Updated declaration
};

#endif // REGISTERMESSAGESTATE_HPP
