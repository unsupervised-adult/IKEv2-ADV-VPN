from flask import Flask, request, jsonify
from tasks import process_okta_event_task 

app = Flask(__name__)

@app.route('/okta/event-hook/', methods=['POST'])
def okta_event_hook():
    try:
        event_data = request.json
        process_okta_event_task.delay(event_data)
        return jsonify({"message": "Event received successfully"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500
