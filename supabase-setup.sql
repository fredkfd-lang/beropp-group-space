-- BerOpp Group Space database setup
-- Run this entire file in Supabase Dashboard > SQL Editor > New query.
-- It creates separate BerOpp Group Space tables; it does not touch other BerOpp data.

create extension if not exists pgcrypto;

create table if not exists public.beropp_profiles (
  user_id uuid primary key references auth.users(id) on delete cascade,
  display_name text not null check (char_length(display_name) between 1 and 50),
  created_at timestamptz not null default now()
);
create table if not exists public.beropp_groups (
  id uuid primary key default gen_random_uuid(),
  name text not null check (char_length(name) between 1 and 70),
  invite_code text not null unique,
  owner_id uuid not null references auth.users(id) on delete cascade,
  created_at timestamptz not null default now()
);
create table if not exists public.beropp_group_members (
  group_id uuid not null references public.beropp_groups(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  display_name text not null check (char_length(display_name) between 1 and 50),
  role text not null default 'member' check (role in ('owner','member')),
  joined_at timestamptz not null default now(),
  primary key (group_id,user_id)
);
create table if not exists public.beropp_group_messages (
  id uuid primary key default gen_random_uuid(),
  group_id uuid not null references public.beropp_groups(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  display_name text not null,
  body text not null check (char_length(body) between 1 and 1000),
  created_at timestamptz not null default now()
);
create index if not exists beropp_messages_group_time_idx on public.beropp_group_messages(group_id,created_at);
create table if not exists public.beropp_gift_assignments (
  group_id uuid not null references public.beropp_groups(id) on delete cascade,
  giver_user_id uuid not null references auth.users(id) on delete cascade,
  receiver_user_id uuid not null references auth.users(id) on delete cascade,
  receiver_name text not null,
  created_at timestamptz not null default now(),
  primary key (group_id,giver_user_id),
  check (giver_user_id <> receiver_user_id)
);

alter table public.beropp_profiles enable row level security;
alter table public.beropp_groups enable row level security;
alter table public.beropp_group_members enable row level security;
alter table public.beropp_group_messages enable row level security;
alter table public.beropp_gift_assignments enable row level security;

drop policy if exists "profile read own" on public.beropp_profiles;
create policy "profile read own" on public.beropp_profiles for select to authenticated using (user_id = auth.uid());
drop policy if exists "profile insert own" on public.beropp_profiles;
create policy "profile insert own" on public.beropp_profiles for insert to authenticated with check (user_id = auth.uid());
drop policy if exists "profile update own" on public.beropp_profiles;
create policy "profile update own" on public.beropp_profiles for update to authenticated using (user_id = auth.uid()) with check (user_id = auth.uid());

create or replace function public.beropp_is_group_member(p_group_id uuid,p_user_id uuid)
returns boolean language sql stable security definer set search_path=public,auth
as $$ select exists(select 1 from public.beropp_group_members where group_id=p_group_id and user_id=p_user_id); $$;
revoke all on function public.beropp_is_group_member(uuid,uuid) from public;
grant execute on function public.beropp_is_group_member(uuid,uuid) to authenticated;

drop policy if exists "groups read when member" on public.beropp_groups;
create policy "groups read when member" on public.beropp_groups for select to authenticated using (owner_id=auth.uid() or public.beropp_is_group_member(id,auth.uid()));
drop policy if exists "groups create own" on public.beropp_groups;
create policy "groups create own" on public.beropp_groups for insert to authenticated with check (owner_id=auth.uid());
drop policy if exists "owner update group" on public.beropp_groups;
create policy "owner update group" on public.beropp_groups for update to authenticated using (owner_id=auth.uid()) with check (owner_id=auth.uid());
drop policy if exists "owner delete group" on public.beropp_groups;
create policy "owner delete group" on public.beropp_groups for delete to authenticated using (owner_id=auth.uid());

drop policy if exists "members read own groups" on public.beropp_group_members;
create policy "members read own groups" on public.beropp_group_members for select to authenticated using (user_id=auth.uid() or public.beropp_is_group_member(group_id,auth.uid()));
drop policy if exists "owner adds initial member" on public.beropp_group_members;
create policy "owner adds initial member" on public.beropp_group_members for insert to authenticated with check (user_id=auth.uid() and role='owner' and exists(select 1 from public.beropp_groups g where g.id=group_id and g.owner_id=auth.uid()));
-- Joining other groups happens through the security-definer RPC below.

drop policy if exists "members read group chat" on public.beropp_group_messages;
create policy "members read group chat" on public.beropp_group_messages for select to authenticated using (public.beropp_is_group_member(group_id,auth.uid()));
drop policy if exists "members send group chat" on public.beropp_group_messages;
create policy "members send group chat" on public.beropp_group_messages for insert to authenticated with check (user_id=auth.uid() and public.beropp_is_group_member(group_id,auth.uid()) and exists(select 1 from public.beropp_group_members m where m.group_id=beropp_group_messages.group_id and m.user_id=auth.uid() and m.display_name=beropp_group_messages.display_name));

drop policy if exists "giver sees own assignment" on public.beropp_gift_assignments;
create policy "giver sees own assignment" on public.beropp_gift_assignments for select to authenticated using (giver_user_id=auth.uid());

create or replace function public.beropp_create_group(p_name text,p_display_name text)
returns public.beropp_groups
language plpgsql security definer set search_path=public,auth
as $
declare g public.beropp_groups; invite text;
begin
  if auth.uid() is null then raise exception 'Sign in first'; end if;
  if p_name is null or char_length(trim(p_name)) not between 1 and 70 then raise exception 'Group name must be 1-70 characters'; end if;
  if p_display_name is null or char_length(trim(p_display_name)) not between 1 and 50 then raise exception 'Enter a display name (1-50 characters)'; end if;
  invite := upper(substr(replace(gen_random_uuid()::text,'-',''),1,8));
  insert into public.beropp_profiles(user_id,display_name) values(auth.uid(),trim(p_display_name))
    on conflict(user_id) do update set display_name=excluded.display_name;
  insert into public.beropp_groups(name,owner_id,invite_code) values(trim(p_name),auth.uid(),invite) returning * into g;
  insert into public.beropp_group_members(group_id,user_id,display_name,role) values(g.id,auth.uid(),trim(p_display_name),'owner');
  return g;
end;
$;

create or replace function public.beropp_join_group(p_invite_code text,p_display_name text)
returns public.beropp_groups
language plpgsql
security definer
set search_path=public,auth
as $$
declare g public.beropp_groups;
begin
  if auth.uid() is null then raise exception 'Sign in first'; end if;
  if p_display_name is null or char_length(trim(p_display_name)) not between 1 and 50 then raise exception 'Enter a display name (1-50 characters)'; end if;
  select * into g from public.beropp_groups where invite_code=upper(trim(p_invite_code));
  if not found then raise exception 'Invitation code not found'; end if;
  insert into public.beropp_profiles(user_id,display_name) values(auth.uid(),trim(p_display_name))
  on conflict(user_id) do update set display_name=excluded.display_name;
  insert into public.beropp_group_members(group_id,user_id,display_name,role)
  values(g.id,auth.uid(),trim(p_display_name),'member')
  on conflict(group_id,user_id) do nothing;
  return g;
end;
$$;

create or replace function public.beropp_run_secret_gift_draw(p_group_id uuid)
returns jsonb
language plpgsql
security definer
set search_path=public,auth
as $$
declare g public.beropp_groups; n integer; ids uuid[]; names text[]; i integer; shift_by integer;
begin
  if auth.uid() is null then raise exception 'Sign in first'; end if;
  select * into g from public.beropp_groups where id=p_group_id;
  if not found then raise exception 'Group not found'; end if;
  if g.owner_id<>auth.uid() then raise exception 'Only the group owner can run the draw'; end if;
  if exists(select 1 from public.beropp_gift_assignments where group_id=p_group_id) then raise exception 'The draw has already been run'; end if;
  select count(*) into n from public.beropp_group_members where group_id=p_group_id;
  if n<2 then raise exception 'At least two members are required'; end if;
  -- Keep each user id paired with the matching display name in one randomized order.
  select array_agg(user_id order by shuffle_order),array_agg(display_name order by shuffle_order) into ids,names
  from (select user_id,display_name,row_number() over(order by random()) as shuffle_order from public.beropp_group_members where group_id=p_group_id) s;
  shift_by := 1 + floor(random()*(n-1))::integer;
  for i in 1..n loop
    insert into public.beropp_gift_assignments(group_id,giver_user_id,receiver_user_id,receiver_name)
    values(p_group_id,ids[i],ids[((i-1+shift_by) % n)+1],names[((i-1+shift_by) % n)+1]);
  end loop;
  return jsonb_build_object('success',true,'members',n);
end;
$$;

revoke all on function public.beropp_create_group(text,text) from public;
grant execute on function public.beropp_create_group(text,text) to authenticated;
revoke all on function public.beropp_join_group(text,text) from public;
revoke all on function public.beropp_run_secret_gift_draw(uuid) from public;
grant execute on function public.beropp_join_group(text,text) to authenticated;
grant execute on function public.beropp_run_secret_gift_draw(uuid) to authenticated;

grant select,insert,update on public.beropp_profiles to authenticated;
grant select,insert,update,delete on public.beropp_groups to authenticated;
grant select,insert on public.beropp_group_members to authenticated;
grant select,insert on public.beropp_group_messages to authenticated;
grant select on public.beropp_gift_assignments to authenticated;
