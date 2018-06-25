import asyncio
from prompt_toolkit import prompt
from prompt_toolkit.eventloop.defaults import use_asyncio_event_loop
from prompt_toolkit.patch_stdout import patch_stdout

# Tell prompt_toolkit to use the asyncio event loop.
use_asyncio_event_loop()

async def my_coroutine():
    while True:
        with patch_stdout():
            result = await prompt('Say something: ', async_=True)
        print('You said: %s' % result)

if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    loop.run_until_complete(my_coroutine())
