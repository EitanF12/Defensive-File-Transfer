#ifndef MESSAGEHANDLER_HPP
#define MESSAGEHANDLER_HPP

#include "State.hpp"
#include <string>

class MessageHandler {//it is a statesHandler
private:
    State* currentState = nullptr;

public:
    MessageHandler() = default;
    ~MessageHandler();
    void setState(State* state);
    State* getState();
};

#endif // MESSAGEHANDLER_HPP
 