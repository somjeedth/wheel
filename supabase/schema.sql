-- Prize wheel database (Supabase / Postgres).
-- Clients can only READ wheel_prizes / wheel_claims; every write goes through the functions below.
-- After running this, set the admin passcode (never commit the real one):
--   insert into public.wheel_settings (id, admin_pin_hash)
--   values (1, extensions.crypt('YOUR-PASSCODE', extensions.gen_salt('bf')))
--   on conflict (id) do update set admin_pin_hash = excluded.admin_pin_hash;

create table public.wheel_prizes (
  id   text primary key,
  name text not null check (char_length(name) between 1 and 40),
  at   bigint not null default (extract(epoch from clock_timestamp()) * 1000)::bigint
);
create table public.wheel_claims (
  item_id     text primary key references public.wheel_prizes(id) on delete cascade,
  player_id   text not null,
  player_name text not null,
  at          bigint not null
);
create table public.wheel_settings (
  id             int primary key default 1 check (id = 1),
  admin_pin_hash text not null
);

alter table public.wheel_prizes   enable row level security;
alter table public.wheel_claims   enable row level security;
alter table public.wheel_settings enable row level security;
create policy "wheel prizes are public" on public.wheel_prizes for select to anon, authenticated using (true);
create policy "wheel claims are public" on public.wheel_claims for select to anon, authenticated using (true);
revoke insert, update, delete, truncate on public.wheel_prizes, public.wheel_claims from anon, authenticated;
revoke all on public.wheel_settings from anon, authenticated;

create or replace function public.wheel_is_admin(p_pin text) returns boolean
language sql stable security definer set search_path = '' as $$
  select exists (select 1 from public.wheel_settings s
                 where s.admin_pin_hash = extensions.crypt(coalesce(p_pin, ''), s.admin_pin_hash));
$$;

-- Draw one random unclaimed prize atomically (row lock + primary key: two people can never get the same item).
create or replace function public.wheel_claim(p_player text, p_name text)
returns table (item_id text, name text)
language plpgsql volatile security definer set search_path = '' as $$
declare v_id text; v_name text; i int := 0;
begin
  if p_player is null or char_length(p_player) not between 8 and 64 then raise exception 'invalid player'; end if;
  p_name := left(btrim(coalesce(p_name, '')), 40);
  if p_name = '' then raise exception 'name required'; end if;
  loop
    i := i + 1;
    select p.id, p.name into v_id, v_name
      from public.wheel_prizes p
     where not exists (select 1 from public.wheel_claims c where c.item_id = p.id)
     order by random() limit 1
     for update of p skip locked;
    if v_id is null then return; end if;
    begin
      insert into public.wheel_claims (item_id, player_id, player_name, at)
      values (v_id, p_player, p_name, (extract(epoch from clock_timestamp()) * 1000)::bigint);
      item_id := v_id; name := v_name; return next; return;
    exception when unique_violation then
      if i >= 5 then raise; end if;
    end;
  end loop;
end $$;

create or replace function public.wheel_unclaim(p_item text, p_player text) returns boolean
language plpgsql volatile security definer set search_path = '' as $$
begin
  delete from public.wheel_claims where item_id = p_item and player_id = p_player;
  return found;
end $$;

create or replace function public.wheel_admin_unclaim(p_pin text, p_item text) returns boolean
language plpgsql volatile security definer set search_path = '' as $$
begin
  if not public.wheel_is_admin(p_pin) then raise exception 'not admin'; end if;
  delete from public.wheel_claims where item_id = p_item;
  return found;
end $$;

create or replace function public.wheel_admin_add(p_pin text, p_name text, p_qty int) returns int
language plpgsql volatile security definer set search_path = '' as $$
declare k int; base bigint := (extract(epoch from clock_timestamp()) * 1000)::bigint;
begin
  if not public.wheel_is_admin(p_pin) then raise exception 'not admin'; end if;
  p_name := left(btrim(coalesce(p_name, '')), 40);
  if p_name = '' then raise exception 'name required'; end if;
  if p_qty is null or p_qty < 1 or p_qty > 50 then raise exception 'qty 1-50'; end if;
  if (select count(*) from public.wheel_prizes) + p_qty > 500 then raise exception 'too many prizes'; end if;
  for k in 0 .. p_qty - 1 loop
    insert into public.wheel_prizes (id, name, at)
    values ('p' || base::text || '-' || k || '-' || substr(md5(random()::text), 1, 4), p_name, base + k);
  end loop;
  return p_qty;
end $$;

create or replace function public.wheel_admin_remove_one(p_pin text, p_name text) returns boolean
language plpgsql volatile security definer set search_path = '' as $$
declare v_id text;
begin
  if not public.wheel_is_admin(p_pin) then raise exception 'not admin'; end if;
  select p.id into v_id from public.wheel_prizes p
   where p.name = p_name and not exists (select 1 from public.wheel_claims c where c.item_id = p.id)
   order by p.at desc limit 1;
  if v_id is null then return false; end if;
  delete from public.wheel_prizes where id = v_id;
  return true;
end $$;

create or replace function public.wheel_admin_reset(p_pin text) returns void
language plpgsql volatile security definer set search_path = '' as $$
begin
  if not public.wheel_is_admin(p_pin) then raise exception 'not admin'; end if;
  delete from public.wheel_claims where true;
end $$;

revoke execute on function public.wheel_is_admin(text), public.wheel_claim(text, text), public.wheel_unclaim(text, text),
  public.wheel_admin_unclaim(text, text), public.wheel_admin_add(text, text, int), public.wheel_admin_remove_one(text, text),
  public.wheel_admin_reset(text) from public;
grant execute on function public.wheel_is_admin(text), public.wheel_claim(text, text), public.wheel_unclaim(text, text),
  public.wheel_admin_unclaim(text, text), public.wheel_admin_add(text, text, int), public.wheel_admin_remove_one(text, text),
  public.wheel_admin_reset(text) to anon, authenticated;

alter publication supabase_realtime add table public.wheel_prizes, public.wheel_claims;

insert into public.wheel_prizes (id, name, at) values
 ('i01','หมอนอิง',0),('i02','หมอนอิง',1),('i03','กระเป๋าเดินทาง',2),('i04','หมวก',3),('i05','กระเป๋าสะพาย',4),
 ('i06','แก้วชมพู',5),('i07','แก้วฟ้า',6),('i08','แก้วส้ม',7),('i09','แก้วชมพู',8),('i10','แก้วฟ้า',9),
 ('i11','แก้วส้ม',10),('i12','แก้วชมพู',11);
