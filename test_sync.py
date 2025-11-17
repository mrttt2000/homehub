from app import create_app

app = create_app()
client = app.test_client()

with app.app_context():
    r = client.get('/calendar')
    print('Calendar page status:', r.status_code)
    print('Has FullCalendar:', b'fullcalendar' in r.data.lower())
    print('Has event modal:', b'eventModal' in r.data)
