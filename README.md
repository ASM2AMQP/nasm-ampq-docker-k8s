# Assembly ❤️ AMQP

<img alt="crash'n burn" src="https://repository-images.githubusercontent.com/1009943771/d545ed91-cb90-4715-b4a4-0e4f4418f94f" style="width: 100%; height: auto;" />

## Rationale

While working on the integration of a complex distributed task queue in a design-by-committee meeting, I wondered out loud why we parse AMQP messages more or less directly instead of using higher-level abstractions like Spring Integration or Celery.

A colleague argued that it wasn't a problem, and also it would be easy to integrate multiple languages, and the target programming languages would be able to handle everything just fine.

I begged to differ and pushed the whole thing up a notch: "**technically, one *could* even parse AMQP messages in assembly** if one were inclined to".

So long story short: this project was born as proof that low-level messaging integration is possible, even close to bare metal. **Because who wouldn't need that?**

## What's Inside

- The producer and consumer **[./amqp.asm](./amqp.asm)** communicate via AMQP messages,
- Docker Compose or Kubernetes (in the k3s incarnation) to orchestrate everything easily.

## How to Run

Two ways to start it: Docker or Kubernetes

### Kubernetes

Who doesn't run their assembly programs in Kubernetes? This way processes won't annoy you with their speed, and... when they crash!

So, fire up the cluster:

```bash
bash deploy.sh
```

*If you need a container registry to run it, check out: [setup-k3s-with-registry.sh](./setup-k3s-with-registry.sh)*

### Docker

If you'd rather see some output printed to your console, just start Docker Compose:

```bash
docker compose up --build
```

---

Have fun exploring the wild side of AMQP!
