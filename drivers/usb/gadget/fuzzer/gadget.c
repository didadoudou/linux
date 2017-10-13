#include <linux/module.h>
#include <linux/refcount.h>
#include <linux/delay.h>
#include <linux/usb/gadget.h>

#include "gadget.h"

#define DRIVER_DESC "USB fuzzer gadget"
#define DRIVER_NAME "usb-fuzzer-gadget"

MODULE_DESCRIPTION(DRIVER_DESC);
MODULE_AUTHOR("Andrey Konovalov");
MODULE_LICENSE("GPL");

#if 1
#define print_debug(fmt, args...) pr_err(fmt, ##args)
#else
#define print_debug(fmt, args...)
#endif

/*----------------------------------------------------------------------*/

enum dev_state {
	STATE_DEV_INVALID = 0,
	STATE_DEV_CREATED,
	STATE_DEV_RUNNING,
	STATE_DEV_STOPPED,
	STATE_DEV_FAILED
};

struct gadget_dev {
	spinlock_t			lock;
	refcount_t			count;
	enum dev_state			state;
	bool				in_progress;

	const char			*chip;
	struct usb_gadget_driver	driver;
	struct usb_gadget		*gadget;
	struct usb_request		*req;
	bool				setup_pending;

	void 				*user_data;
	void (*setup)(void *user_data, const struct usb_ctrlrequest *,
			struct usb_fuzzer_gadget_response *);
};

static struct gadget_dev *dev_new(void)
{
	struct gadget_dev *dev;
	dev = kzalloc(sizeof(*dev), GFP_KERNEL);
	if (!dev)
		return NULL;
	spin_lock_init(&dev->lock);
	refcount_set(&dev->count, 1);
	return dev;
}

static inline void dev_get(struct gadget_dev *dev)
{
	refcount_inc(&dev->count);
}

static void dev_put(struct gadget_dev *dev)
{
	if (likely(!refcount_dec_and_test(&dev->count)))
		return;
	if (dev->chip)
		kfree(dev->chip);
	if (dev->req) {
		if (dev->setup_pending)
			usb_ep_dequeue(dev->gadget->ep0, dev->req);
		usb_ep_free_request(dev->gadget->ep0, dev->req);
	}
	kfree(dev);
}

static int dev_read_state(struct gadget_dev *dev)
{
	return READ_ONCE(dev->state);
}

static int dev_acquire_state(struct gadget_dev *dev, int curr)
{
	spin_lock_irq(&dev->lock);
	if (dev->in_progress || READ_ONCE(dev->state) != curr) {
		spin_unlock_irq(&dev->lock);
		return -EBUSY;
	}
	dev->in_progress = true;
	spin_unlock_irq(&dev->lock);
	return 0;
}

static void dev_release_state(struct gadget_dev *dev, int new)
{
	spin_lock_irq(&dev->lock);
	WRITE_ONCE(dev->state, new);
	dev->in_progress = false;
	spin_unlock_irq(&dev->lock);
}

/*----------------------------------------------------------------------*/

static void gadget_ep0_complete(struct usb_ep *ep, struct usb_request *req)
{
	struct gadget_dev *dev = req->context;
	dev->setup_pending = false;
}

static void gadget_unbind(struct usb_gadget *gadget)
{
	struct gadget_dev *dev = get_gadget_data(gadget);

	print_debug("uf: gadget_unbind\n");

	BUG_ON(!dev);
	set_gadget_data(gadget, NULL);
	dev_put(dev);

	print_debug("uf: gadget_unbind = void\n");
}

static int gadget_bind(struct usb_gadget *gadget,
			struct usb_gadget_driver *driver)
{
	int ret = 0;
	struct gadget_dev *dev = container_of(driver, struct gadget_dev, driver);

	print_debug("uf: gadget_bind\n");

	if (strcmp(gadget->name, dev->chip) != 0) {
		ret = -ENODEV;
		goto out;
	}
	set_gadget_data(gadget, dev);
	dev->gadget = gadget;
	dev->req = usb_ep_alloc_request(gadget->ep0, GFP_KERNEL);
	if (!dev->req) {
		ret = -ENOMEM;
		goto out_unbind;
	}
	dev->req->context = dev;
	dev->req->complete = gadget_ep0_complete;
	dev_get(dev);

	goto out;

out_unbind:
	gadget_unbind(gadget);
out:
	print_debug("uf: gadget_bind = %d\n", ret);
	return ret;
}

static int gadget_setup(struct usb_gadget *gadget,
			const struct usb_ctrlrequest *ctrl)
{
	int ret = 0;
	struct gadget_dev *dev = get_gadget_data(gadget);
	struct usb_fuzzer_gadget_response response;

	if (!dev)
		return 0;

	print_debug("uf: gadget_setup\n");

	dev->req->context = dev;
	response.length = 0;
	response.data = 0;
	dev->setup(dev->user_data, ctrl, &response);
	if (response.state != 0)
		usb_gadget_set_state(gadget, response.state);
	if (response.power != 0)
		usb_gadget_vbus_draw(gadget, response.power);
	dev->req->buf = response.data;
	dev->req->length = min(response.length, ctrl->wLength);
	dev->req->zero = dev->req->length < ctrl->wLength;

	ret = usb_ep_queue(gadget->ep0, dev->req, GFP_ATOMIC);
	if (ret == 0)
		dev->setup_pending = true;

	print_debug("uf: gadget_setup = %d\n", ret);
	return ret;
}

static void gadget_disconnect(struct usb_gadget *gadget)
{
	print_debug("uf: gadget_disconnect\n");
	return;
}

static void gadget_suspend(struct usb_gadget *gadget)
{
	print_debug("uf: gadget_suspend\n");
	return;
}

/*----------------------------------------------------------------------*/

static struct usb_gadget_driver gadget_driver = {
	.function	= DRIVER_DESC,
	.bind		= gadget_bind,
	.unbind		= gadget_unbind,
	.setup		= gadget_setup,
	.reset		= gadget_disconnect,
	.disconnect	= gadget_disconnect,
	.suspend	= gadget_suspend,

	.driver	= {
		.name	= DRIVER_NAME,
	},
};

void *usb_fuzzer_gadget_init(struct usb_fuzzer_gadget_info *info)
{
	struct gadget_dev *dev = NULL;

	print_debug("uf: usb_fuzzer_gadget_init\n");

	dev = dev_new();
	if (!dev) {
		dev = ERR_PTR(-ENOMEM);
		goto out;
	}
	dev->chip = usb_get_gadget_udc_name();
	if (!dev->chip) {
		dev_put(dev);
		dev = ERR_PTR(-ENODEV);
		goto out;
	}
	memcpy(&dev->driver, &gadget_driver, sizeof(gadget_driver));
	dev->driver.max_speed = info->speed;
	dev->user_data = info->user_data;
	dev->setup = info->setup;
	dev->state = STATE_DEV_CREATED;

out:
	print_debug("uf: usb_fuzzer_gadget_init = %p\n", dev);
	return dev;
}

int usb_fuzzer_gadget_run(void *gadget)
{
	int ret = 0;
	struct gadget_dev *dev = (struct gadget_dev *)gadget;

	print_debug("uf: usb_fuzzer_gadget_run\n");

	if (!dev) {
		ret = -EINVAL;
		goto out;
	}
	ret = dev_acquire_state(dev, STATE_DEV_CREATED);
	if (ret < 0)
		goto out;
	ret = usb_gadget_probe_driver(&dev->driver);
	if (ret != 0)
		dev_release_state(dev, STATE_DEV_FAILED);
	else
		dev_release_state(dev, STATE_DEV_RUNNING);

out:
	print_debug("uf: usb_fuzzer_gadget_run = %d\n", ret);
	return ret;
}

int usb_fuzzer_gadget_stop(void *gadget)
{
	int ret = 0;
	struct gadget_dev *dev = (struct gadget_dev *)gadget;

	print_debug("uf: usb_fuzzer_gadget_stop\n");

	if (!dev) {
		ret = -EINVAL;
		goto out;
	}
	if (dev_read_state(dev) == STATE_DEV_FAILED)
		goto out;
	ret = dev_acquire_state(dev, STATE_DEV_RUNNING);
	if (ret < 0)
		goto out;
	usb_gadget_unregister_driver(&dev->driver);
	dev_release_state(dev, STATE_DEV_STOPPED);

out:
	print_debug("uf: usb_fuzzer_gadget_stop = %d\n", ret);
	return ret;

}

void usb_fuzzer_gadget_destroy(void *gadget)
{
	int ret = 0, attempts = 0;
	struct gadget_dev *dev = (struct gadget_dev *)gadget;

	print_debug("uf: usb_fuzzer_gadget_destroy\n");

	if (!dev) {
		ret = -EINVAL;
		goto out;
	}
	while (1) {
		ret = usb_fuzzer_gadget_stop(dev);
		if (ret == 0)
			break;
		if (attempts++ == 100) {
			WARN_ON(1);
			break;
		}
		msleep(1);
	}
	if (ret != 0)
		usb_gadget_unregister_driver(&dev->driver);

out:
	print_debug("uf: usb_fuzzer_gadget_destroy = %d\n", ret);
}
