import { Entity, PrimaryGeneratedColumn, Column, OneToMany } from 'typeorm';
import { Project } from '../../project/entities/project.entity';
import { Post } from '../../post/entities/post.entity';
import { Like } from '../../like/entities/like.entity';
import { Comment } from '../../comment/entities/comment.entity';
import { Bookmark } from '../../bookmark/entities/bookmark.entity';
import { Follow } from '../../follow/entities/follow.entity';

@Entity('users')
export class User {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ unique: true })
  email: string;

  @Column()
  password: string;

  @Column()
  name: string;

  @Column({ nullable: true })
  profilePicture: string;

  @Column({ nullable: true })
  bio: string;

  @Column({ type: 'enum', enum: ['Free', 'Pro'], default: 'Free' })
  planType: string;

  @Column({ default: 0 })
  renderCredits: number;

  @OneToMany(() => Project, (project) => project.user)
  projects: Project[];

  @OneToMany(() => Post, (post) => post.user)
  posts: Post[];

  @OneToMany(() => Like, (like) => like.user)
  likes: Like[];

  @OneToMany(() => Comment, (comment) => comment.user)
  comments: Comment[];

  @OneToMany(() => Bookmark, (bookmark) => bookmark.user)
  bookmarks: Bookmark[];

  @OneToMany(() => Follow, (follow) => follow.follower)
  following: Follow[];

  @OneToMany(() => Follow, (follow) => follow.following)
  followers: Follow[];
}
