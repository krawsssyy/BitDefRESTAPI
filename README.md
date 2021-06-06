## Requirements
```bash
pip3 install flask
pip3 install flask_sqlalchemy
pip3 install flask_login
```

## Running The App

```bash
python main.py
```

## Viewing The App

Go to `http://127.0.0.1:5000`

### Queries

Adding : http://127.0.0.1:5000/add/'collection'
Viewing : http://127.0.0.1:5000/view/'collection'
Deleting : http://127.0.0.1:5000/delete/'collection'/'collectionID'


### Types of producer
On sign-up, the email must contain @malware for modifiying the malware collection, @tool for the tools one, @indicator, @rel and @vuln for their respective collections. Everyone can view the collections.
