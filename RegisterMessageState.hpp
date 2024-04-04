#ifndef REGISTERMESSAGESTATE_HPP
#define REGISTERMESSAGESTATE_HPP

#include "State.hpp"
#include <string>

class RegisterMessageState : public State {
public:
    
    RegisterMessageState();
    
    std::string createMessage(const std::string& payload) override; 
};

#endif // REGISTERMESSAGESTATE_HPP
