from behave.fixture import fixture
from selenium import webdriver
from wsgiref import simple_server
from 

@fixture
def chrome_browser(context):
    context.browser = webdriver.Chrome()
    yield context.browser

    # Clean-up fixture
    context.browser.quit()
