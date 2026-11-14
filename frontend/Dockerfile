# syntax=docker/dockerfile:1.7
#
# Cipher Eclipse frontend (Next.js App Router) image
#   docker build -t aliakbarzaidi/cipher-eclipse-frontend:latest ./frontend
#
# REQUIREMENT for Shuja's Next.js app: next.config.(js|mjs|ts) must contain
#     output: "standalone"
# That makes `next build` emit a self-contained server in .next/standalone
# with only the node_modules it actually uses, so the runtime image is
# ~150 MB instead of ~1 GB.
#
# Three stages:
#   deps     - install node_modules from the lockfile (cached until lockfile changes)
#   builder  - run `next build`
#   runner   - minimal Node image with just the standalone output

ARG NODE_VERSION=22-alpine

############################ deps #############################################
FROM node:${NODE_VERSION} AS deps
# No libc6-compat needed: Next.js ships musl builds of its native SWC binary.
# (If you add a glibc-only native package, add: RUN apk add --no-cache libc6-compat)
WORKDIR /app

COPY package.json package-lock.json* yarn.lock* pnpm-lock.yaml* ./
# Use whichever lockfile the team committed. A lockfile is required: it is the
# whole point of reproducible installs ("works on my machine" prevention).
RUN --mount=type=cache,target=/root/.npm \
    --mount=type=cache,target=/root/.cache/yarn \
    --mount=type=cache,target=/root/.local/share/pnpm/store \
    if [ -f package-lock.json ]; then npm ci; \
    elif [ -f yarn.lock ]; then corepack enable yarn && yarn install --frozen-lockfile; \
    elif [ -f pnpm-lock.yaml ]; then corepack enable pnpm && pnpm install --frozen-lockfile; \
    else echo "No lockfile found. Run 'npm install' locally and commit package-lock.json." >&2 && exit 1; \
    fi

############################ builder ##########################################
FROM node:${NODE_VERSION} AS builder
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .

# NEXT_PUBLIC_* variables are inlined into the browser bundle at BUILD time,
# so the backend URL the browser should call must be passed as a build arg.
ARG NEXT_PUBLIC_API_URL=http://localhost:8000
ENV NEXT_PUBLIC_API_URL=${NEXT_PUBLIC_API_URL} \
    NEXT_TELEMETRY_DISABLED=1

RUN if [ -f yarn.lock ]; then corepack enable yarn && yarn build; \
    elif [ -f pnpm-lock.yaml ]; then corepack enable pnpm && pnpm run build; \
    else npm run build; \
    fi \
    && test -f .next/standalone/server.js \
    || (echo "ERROR: .next/standalone/server.js missing. Add output: 'standalone' to next.config." >&2 && exit 1)

# Next copies `public/` only if it exists; make sure the COPY below never fails.
RUN mkdir -p public

############################ runner ###########################################
FROM node:${NODE_VERSION} AS runner
WORKDIR /app

LABEL org.opencontainers.image.title="cipher-eclipse-frontend" \
      org.opencontainers.image.description="Cipher Eclipse Next.js dashboard"

ENV NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1 \
    PORT=3000 \
    HOSTNAME=0.0.0.0

RUN addgroup --system --gid 1001 nodejs \
    && adduser --system --uid 1001 --ingroup nodejs nextjs

# Static assets and the standalone server. .next/static is not included in the
# standalone folder by design, so it is copied separately.
COPY --from=builder --chown=nextjs:nodejs /app/public ./public
COPY --from=builder --chown=nextjs:nodejs /app/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /app/.next/static ./.next/static

USER nextjs
EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD wget -q -O /dev/null http://127.0.0.1:3000/ || exit 1

CMD ["node", "server.js"]
