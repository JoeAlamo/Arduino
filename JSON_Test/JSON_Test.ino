#include <ArduinoJson.h>

#define MAX_JSON_SIZE 100

struct User 
{
  const char *forename;
  const char *surname;
  int age;
  bool married;
};

char user1JSON[MAX_JSON_SIZE];

void setup() {
  struct User user1 = {"Joe", "Bloggs", 30, true};
  serialiseUser(user1, user1JSON, MAX_JSON_SIZE);
  struct User user2;
  deserialiseUser(user2, user1JSON);
}

void serialiseUser(const struct User& user, char* json, size_t maxSize)
{
  StaticJsonBuffer<MAX_JSON_SIZE> jsonBuffer;
  JsonObject& userJson = jsonBuffer.createObject();
  userJson["forename"] = user.forename;
  userJson["surname"] = user.surname;
  userJson["age"] = user.age;
  userJson["married"] = user.married;
  userJson.printTo(json, maxSize);
}

bool deserialiseUser(struct User& user, char* json)
{
  StaticJsonBuffer<MAX_JSON_SIZE> jsonBuffer;
  JsonObject& userJson = jsonBuffer.parseObject(json);
  user.forename = userJson["forename"];
  user.surname = userJson["surname"];
  user.age = userJson["age"];
  user.married = userJson["married"];
  return userJson.success();
}

void loop() {
}
