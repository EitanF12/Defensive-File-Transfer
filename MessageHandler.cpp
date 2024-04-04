#include "MessageHandler.hpp"

MessageHandler::~MessageHandler() { delete currentState; }

void MessageHandler::setState(State* state) {
    delete currentState;
    currentState = state;
}

State* MessageHandler::getState()
{
    return currentState;
}

