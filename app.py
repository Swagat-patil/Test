import os
from flask import Flask
app = Flask(__name__)

@app.route("/")
def main():
  return "Welcome!"

@app.route("/how are you")
def hello():
  return "i am good!"

if __name__ "" "__main__":
 app.run()
