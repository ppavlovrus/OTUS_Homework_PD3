# Scoring API
1. ## Running api.py
    I run api.py in Pycharm with Python 3.9 interpreter


2. ## Example of requests
    Omline Score:
    ```shell
    HTTP Body:
    {
      "account": "horns&hoofs",
      "login": "h&f",
      "method": "online_score",
      "token": "55cc9ce545bcd144300fe9efc28e65d415b923ebb6be1e19d2750a2c03e80dd209a27954dca045e5bb12418e7d89b6d718a9e35af34e14e1d5bcd5a08f21fc95",
      "arguments": {
        "phone": "79175002040",
        "email": "stupnikov@otus.ru",
        "first_name": "Стансилав",
        "last_name": "Ступников",
        "birthday": "01.01.1990",
        "gender": 1
      }
    }
    ```
    Interest:

    ```shell
    HTTP Body:
     {
      "account": "horns&hoofs",
      "login": "h&f",
      "method": "clients_interests",
      "token": "55cc9ce545bcd144300fe9efc28e65d415b923ebb6be1e19d2750a2c03e80dd209a27954dca045e5bb12418e7d89b6d718a9e35af34e14e1d5bcd5a08f21fc95",
      "arguments": {
        "client_ids": [
          1,
          2,
          3,
          4
        ],
        "date": "20.07.2017"
      }
    }
    ```